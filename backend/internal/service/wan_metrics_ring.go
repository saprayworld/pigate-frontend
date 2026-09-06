package service

import (
	"sync"
	"time"

	"pigate/internal/model"
)

// maxRawSamplesPerUplink bounds how many of the most recent raw probe
// samples (model.WanProbeSample, one per probe round) are kept per uplink —
// enough for a "recent activity" view without the ring growing unbounded
// across a long uptime (docs/ref/todo/multi-wan-failover-plan.md Task 6).
const maxRawSamplesPerUplink = 360

// wanMetricBucket is one trafficDetailBucketSpan (5-minute) summary bucket
// of latency/jitter/loss for a single WAN uplink, mirroring the
// roll-and-merge shape of trafficDetailBucket (traffic_stats.go addBucket)
// but storing running sums instead of byte counters so the average can be
// computed on read without re-scanning every raw sample.
type wanMetricBucket struct {
	ts string // RFC3339, truncated to trafficDetailBucketSpan

	// sumLatencyMs/latencySamples are accumulated only from *received*
	// probes within this bucket (a round with Received==0 contributes
	// nothing to latency, only to loss below).
	sumLatencyMs   float64
	latencySamples int
	maxLatencyMs   float64

	// sumJitterMs/jitterSamples are accumulated only from rounds whose
	// MetricQuality is "full" (D-6 — TCP connect-only rounds never produce a
	// meaningful jitter figure and must not silently count as 0).
	sumJitterMs   float64
	jitterSamples int

	totalSent     int
	totalReceived int
}

// WanUplinkMetricsRing is the RAM-only, per-uplink store of raw probe
// samples and 5-minute summary buckets backing GET /api/wan/metrics. Per D-3
// (docs/ref/todo/multi-wan-failover-plan.md, tech_stack_design.md §8) this
// file MUST NEVER import internal/db or persist anything to SQLite — a
// pigate restart legitimately resets all history here, same as
// TrafficStatsService's bucket ring (traffic_stats.go) and logs/ringbuffer.go.
//
// It deliberately reuses traffic_stats.go's window/axis helpers
// (statsWindowBucketCount, statsSeriesAxis, statsSeriesIndex,
// trafficDetailBucketSpan/Max) since both rings share the exact same 5min x
// 288-bucket (24h) shape — see those functions' doc comments for the shared
// "carry to nearest edge" invariant that keeps sum(series) consistent with
// the underlying buckets.
type WanUplinkMetricsRing struct {
	mu      sync.RWMutex
	raw     map[string][]model.WanProbeSample // uplinkID -> ring, oldest first, capped at maxRawSamplesPerUplink
	buckets map[string][]wanMetricBucket      // uplinkID -> ring, oldest first, capped at trafficDetailBucketMax
}

// NewWanUplinkMetricsRing constructs an empty ring store.
func NewWanUplinkMetricsRing() *WanUplinkMetricsRing {
	return &WanUplinkMetricsRing{
		raw:     make(map[string][]model.WanProbeSample),
		buckets: make(map[string][]wanMetricBucket),
	}
}

// Add records one probe round's result for uplinkID: it appends the raw
// sample (evicting the oldest once maxRawSamplesPerUplink is exceeded) and
// merges its derived latency/jitter/loss into the current (or a freshly
// rolled) 5-minute bucket for that uplink.
func (r *WanUplinkMetricsRing) Add(uplinkID string, sample model.WanProbeSample) {
	r.mu.Lock()
	defer r.mu.Unlock()

	ring := append(r.raw[uplinkID], sample)
	if len(ring) > maxRawSamplesPerUplink {
		ring = ring[len(ring)-maxRawSamplesPerUplink:]
	}
	r.raw[uplinkID] = ring

	r.addBucketLocked(uplinkID, sample)
}

// addBucketLocked merges sample into the current 5-minute bucket for
// uplinkID (rolling a new one if the clock has moved into the next span),
// evicting the oldest bucket past trafficDetailBucketMax — mirrors
// TrafficStatsService.addBucket. Caller must hold r.mu.
func (r *WanUplinkMetricsRing) addBucketLocked(uplinkID string, sample model.WanProbeSample) {
	when := time.Unix(sample.TimestampUnix, 0)
	ts := when.Truncate(trafficDetailBucketSpan).Format(time.RFC3339)

	avgRTT, maxRTT, jitter, hasJitter := summarizeRTTs(sample.RTTsMs)
	hasFullQuality := sample.MetricQuality == model.WanMetricQualityFull

	buckets := r.buckets[uplinkID]
	if n := len(buckets); n > 0 && buckets[n-1].ts == ts {
		mergeSampleIntoWanBucket(&buckets[n-1], sample, avgRTT, maxRTT, jitter, hasJitter && hasFullQuality)
		r.buckets[uplinkID] = buckets
		return
	}

	b := wanMetricBucket{ts: ts}
	mergeSampleIntoWanBucket(&b, sample, avgRTT, maxRTT, jitter, hasJitter && hasFullQuality)
	buckets = append(buckets, b)
	if len(buckets) > trafficDetailBucketMax {
		buckets = buckets[len(buckets)-trafficDetailBucketMax:]
	}
	r.buckets[uplinkID] = buckets
}

// mergeSampleIntoWanBucket folds one probe round's derived numbers into b.
func mergeSampleIntoWanBucket(b *wanMetricBucket, sample model.WanProbeSample, avgRTT, maxRTT, jitter float64, countJitter bool) {
	b.totalSent += sample.Sent
	b.totalReceived += sample.Received
	if sample.Received > 0 {
		b.sumLatencyMs += avgRTT * float64(sample.Received)
		b.latencySamples += sample.Received
		if maxRTT > b.maxLatencyMs {
			b.maxLatencyMs = maxRTT
		}
	}
	if countJitter {
		b.sumJitterMs += jitter
		b.jitterSamples++
	}
}

// summarizeRTTs computes the average and max of rtts (milliseconds) plus a
// simple jitter proxy (mean absolute difference between consecutive RTTs —
// the same proxy the Task 0 spike snippet used, good enough for a health
// signal, not meant to match RFC 3550's PDV formula exactly). hasJitter is
// false whenever fewer than 2 RTTs are available (nothing to diff).
func summarizeRTTs(rtts []float64) (avg, max, jitter float64, hasJitter bool) {
	if len(rtts) == 0 {
		return 0, 0, 0, false
	}
	sum := 0.0
	for _, v := range rtts {
		sum += v
		if v > max {
			max = v
		}
	}
	avg = sum / float64(len(rtts))
	if len(rtts) < 2 {
		return avg, max, 0, false
	}
	diffSum := 0.0
	for i := 1; i < len(rtts); i++ {
		d := rtts[i] - rtts[i-1]
		if d < 0 {
			d = -d
		}
		diffSum += d
	}
	return avg, max, diffSum / float64(len(rtts)-1), true
}

// RawSamples returns a copy of the most recent raw samples for uplinkID
// (oldest first), or nil if none have been recorded yet.
func (r *WanUplinkMetricsRing) RawSamples(uplinkID string) []model.WanProbeSample {
	r.mu.RLock()
	defer r.mu.RUnlock()
	src := r.raw[uplinkID]
	if len(src) == 0 {
		return nil
	}
	out := make([]model.WanProbeSample, len(src))
	copy(out, src)
	return out
}

// wanSeriesAccum accumulates every bucket that maps to the same series index
// (statsSeriesIndex's "carry to nearest edge" rule can map more than one
// out-of-window bucket onto index 0 or n-1) so Series below sums rather than
// overwrites, mirroring how traffic_stats.go's getTrafficBreakdown builds its
// per-bucket series with "+=" (see traffic_stats.go:1684-1686).
type wanSeriesAccum struct {
	sumLatencyMs   float64
	latencySamples int
	maxLatencyMs   float64
	sumJitterMs    float64
	jitterSamples  int
	totalSent      int
	totalReceived  int
}

// Series returns one model.WanMetricPoint per trailing 5-minute bucket in
// window ("1h".."24h", see statsWindowBucketCount), oldest first, always
// exactly the window's bucket count long regardless of how much history is
// actually recorded yet (empty buckets read back as zero-valued points).
func (r *WanUplinkMetricsRing) Series(uplinkID, window string) []model.WanMetricPoint {
	axisStart, n := statsSeriesAxis(window)

	r.mu.RLock()
	buckets := append([]wanMetricBucket(nil), r.buckets[uplinkID]...)
	r.mu.RUnlock()

	accum := make([]wanSeriesAccum, n)
	for _, b := range buckets {
		idx := statsSeriesIndex(b.ts, axisStart, n)
		a := &accum[idx]
		a.sumLatencyMs += b.sumLatencyMs
		a.latencySamples += b.latencySamples
		if b.maxLatencyMs > a.maxLatencyMs {
			a.maxLatencyMs = b.maxLatencyMs
		}
		a.sumJitterMs += b.sumJitterMs
		a.jitterSamples += b.jitterSamples
		a.totalSent += b.totalSent
		a.totalReceived += b.totalReceived
	}

	points := make([]model.WanMetricPoint, n)
	for i := 0; i < n; i++ {
		points[i].Timestamp = axisStart.Add(time.Duration(i) * trafficDetailBucketSpan).Format(time.RFC3339)
		a := accum[i]
		if a.latencySamples > 0 {
			points[i].AvgLatencyMs = a.sumLatencyMs / float64(a.latencySamples)
			points[i].MaxLatencyMs = a.maxLatencyMs
		}
		if a.jitterSamples > 0 {
			j := a.sumJitterMs / float64(a.jitterSamples)
			points[i].JitterMs = &j
		}
		if a.totalSent > 0 {
			points[i].LossPct = 100 * float64(a.totalSent-a.totalReceived) / float64(a.totalSent)
		}
	}
	return points
}
