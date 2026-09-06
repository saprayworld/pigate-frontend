package service

import (
	"testing"
	"time"

	"pigate/internal/model"
)

func TestWanMetricsRing_RawSamplesEvictOldest(t *testing.T) {
	ring := NewWanUplinkMetricsRing()
	base := time.Now().Add(-time.Duration(maxRawSamplesPerUplink+10) * time.Second)

	for i := 0; i < maxRawSamplesPerUplink+10; i++ {
		ring.Add("wan-1", model.WanProbeSample{
			TimestampUnix: base.Add(time.Duration(i) * time.Second).Unix(),
			Sent:          1, Received: 1, RTTsMs: []float64{10},
			Method: model.WanProbeMethodICMP, MetricQuality: model.WanMetricQualityFull,
		})
	}

	samples := ring.RawSamples("wan-1")
	if len(samples) != maxRawSamplesPerUplink {
		t.Fatalf("expected ring capped at %d, got %d", maxRawSamplesPerUplink, len(samples))
	}
	// The oldest 10 samples (timestamps base..base+9s) must have been
	// evicted — the first remaining sample's timestamp must be base+10s.
	wantFirst := base.Add(10 * time.Second).Unix()
	if samples[0].TimestampUnix != wantFirst {
		t.Errorf("expected oldest sample evicted: first remaining ts=%d, want %d", samples[0].TimestampUnix, wantFirst)
	}
}

func TestWanMetricsRing_RawSamplesEmptyWhenNeverRecorded(t *testing.T) {
	ring := NewWanUplinkMetricsRing()
	if samples := ring.RawSamples("never-seen"); samples != nil {
		t.Errorf("expected nil for an uplink with no recorded samples, got %v", samples)
	}
}

func TestSummarizeRTTs(t *testing.T) {
	avg, max, jitter, hasJitter := summarizeRTTs([]float64{10, 20, 15})
	if avg != 15 {
		t.Errorf("avg = %v, want 15", avg)
	}
	if max != 20 {
		t.Errorf("max = %v, want 20", max)
	}
	if !hasJitter {
		t.Fatal("expected hasJitter=true for 3 samples")
	}
	// |20-10| + |15-20| = 10+5 = 15, / 2 = 7.5
	if jitter != 7.5 {
		t.Errorf("jitter = %v, want 7.5", jitter)
	}

	if _, _, _, hasJitter := summarizeRTTs([]float64{10}); hasJitter {
		t.Error("expected hasJitter=false for a single sample")
	}
	if avg, max, jitter, hasJitter := summarizeRTTs(nil); avg != 0 || max != 0 || jitter != 0 || hasJitter {
		t.Errorf("expected all-zero/false for empty input, got avg=%v max=%v jitter=%v hasJitter=%v", avg, max, jitter, hasJitter)
	}
}

func TestWanMetricsRing_BucketAggregation(t *testing.T) {
	ring := NewWanUplinkMetricsRing()
	now := time.Now().Truncate(trafficDetailBucketSpan).Add(time.Minute) // stays inside the same 5-min bucket

	// Two full-quality (ICMP) samples merged into the same bucket.
	ring.Add("wan-1", model.WanProbeSample{
		TimestampUnix: now.Unix(), Sent: 3, Received: 3, RTTsMs: []float64{10, 20, 30},
		Method: model.WanProbeMethodICMP, MetricQuality: model.WanMetricQualityFull,
	})
	ring.Add("wan-1", model.WanProbeSample{
		TimestampUnix: now.Add(5 * time.Second).Unix(), Sent: 2, Received: 0,
		Method: model.WanProbeMethodICMP, MetricQuality: model.WanMetricQualityFull,
	})

	points := ring.Series("wan-1", "1h")
	last := points[len(points)-1]

	// avg latency of the first sample: (10+20+30)/3 = 20, weighted by
	// Received=3 -> sum=60, count=3; second sample contributes nothing to
	// latency (Received=0). Overall avg = 60/3 = 20.
	if last.AvgLatencyMs != 20 {
		t.Errorf("AvgLatencyMs = %v, want 20", last.AvgLatencyMs)
	}
	if last.MaxLatencyMs != 30 {
		t.Errorf("MaxLatencyMs = %v, want 30", last.MaxLatencyMs)
	}
	// loss: sent=3+2=5, received=3+0=3 -> loss = 2/5 = 40%
	if last.LossPct != 40 {
		t.Errorf("LossPct = %v, want 40", last.LossPct)
	}
	if last.JitterMs == nil {
		t.Fatal("expected JitterMs to be set (full-quality sample present)")
	}
	// |20-10| + |30-20| = 20, / 2 = 10
	if *last.JitterMs != 10 {
		t.Errorf("JitterMs = %v, want 10", *last.JitterMs)
	}
}

func TestWanMetricsRing_ConnectOnlyNeverProducesJitter(t *testing.T) {
	ring := NewWanUplinkMetricsRing()
	now := time.Now()

	ring.Add("wan-2", model.WanProbeSample{
		TimestampUnix: now.Unix(), Sent: 3, Received: 3, RTTsMs: []float64{10, 15, 12},
		Method: model.WanProbeMethodTCP, MetricQuality: model.WanMetricQualityConnectOnly,
	})

	points := ring.Series("wan-2", "1h")
	last := points[len(points)-1]
	if last.JitterMs != nil {
		t.Errorf("expected JitterMs=nil for a connect-only (TCP) sample, got %v", *last.JitterMs)
	}
	// Latency/loss must still be populated even without jitter.
	if last.AvgLatencyMs == 0 {
		t.Error("expected AvgLatencyMs to still be populated for a connect-only sample")
	}
}

func TestWanMetricsRing_SeriesLengthMatchesWindow(t *testing.T) {
	ring := NewWanUplinkMetricsRing()
	points := ring.Series("empty-uplink", "24h")
	if len(points) != 288 {
		t.Errorf("expected 288 points for a 24h window, got %d", len(points))
	}
	for i, p := range points {
		if p.AvgLatencyMs != 0 || p.LossPct != 0 || p.JitterMs != nil {
			t.Errorf("expected zero-valued point at index %d for an uplink with no data, got %+v", i, p)
		}
	}
}

func TestWanMetricsRing_ConcurrentAccessRace(t *testing.T) {
	ring := NewWanUplinkMetricsRing()
	done := make(chan struct{})

	go func() {
		for i := 0; i < 500; i++ {
			ring.Add("wan-race", model.WanProbeSample{
				TimestampUnix: time.Now().Unix(), Sent: 1, Received: 1, RTTsMs: []float64{float64(i % 30)},
				Method: model.WanProbeMethodICMP, MetricQuality: model.WanMetricQualityFull,
			})
		}
		close(done)
	}()

	for i := 0; i < 500; i++ {
		_ = ring.RawSamples("wan-race")
		_ = ring.Series("wan-race", "1h")
	}
	<-done
}
