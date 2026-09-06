import React, { useState, useEffect } from "react"
import { BrowserRouter, Routes, Route, Navigate } from "react-router"
import { Loader2, Shield } from "lucide-react"
import { authService } from "@/services/authService"
import { ThemeProvider } from "@/components/ThemeProvider"
import { AlertDialogProvider } from "@/components/AlertDialogProvider"
import { TooltipProvider } from "@/components/ui/tooltip"
import ShellLayout from "@/components/layout/ShellLayout"
import Dashboard from "@/pages/Dashboard"
import Interfaces from "@/pages/Interfaces"
import StaticRoutes from "@/pages/StaticRoutes"
import DhcpServer from "@/pages/DhcpServer"
import FirewallPolicy from "@/pages/FirewallPolicy"
import LocalInPolicy from "@/pages/LocalInPolicy"
import LocalOutPolicy from "@/pages/LocalOutPolicy"
import PortForwarding from "@/pages/PortForwarding"
import Addresses from "@/pages/Addresses"
import Services from "@/pages/Services"
import SettingsMaintenance from "@/pages/SettingsMaintenance"
import Users from "@/pages/Users"
import Login from "@/pages/Login"
import ApiDocs from "./pages/ApiDocs"
import DNS from "@/pages/DNS"
import DnsServer from "@/pages/DnsServer"
import ForceChangePassword from "@/pages/ForceChangePassword"
import QoS from "@/pages/QoS"
import WanFailover from "@/pages/WanFailover"
import EventLogs from "@/pages/EventLogs"
import ForwardTraffic from "@/pages/ForwardTraffic"
import LocalTraffic from "@/pages/LocalTraffic"
import StatisticsOverview from "@/pages/StatisticsOverview"
import StatisticsTraffic from "@/pages/StatisticsTraffic"
import StatisticsTrafficHost from "@/pages/StatisticsTrafficHost"
import StatisticsFirewall from "@/pages/StatisticsFirewall"
import StatisticsDns from "@/pages/StatisticsDns"
import StatisticsDnsDomain from "@/pages/StatisticsDnsDomain"
import StatisticsDnsClient from "@/pages/StatisticsDnsClient"
import StatisticsCapacity from "@/pages/StatisticsCapacity"
import { SizeIndicatorSystem } from "./components/tailwindIndicator"

// A simple authentication route guard
function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const isAuthenticated = authService.isAuthenticated()
  const mustChangePassword = localStorage.getItem("pigate_must_change_password") === "true"

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />
  }
  if (mustChangePassword) {
    return <Navigate to="/change-password" replace />
  }
  return <>{children}</>
}

// SuperAdminRoute guards super_admin-only pages. This is UX only — the backend
// middleware is the real enforcement — but it prevents a read-only admin from
// landing on a page they can't use.
function SuperAdminRoute({ children }: { children: React.ReactNode }) {
  const role = localStorage.getItem("pigate_role")
  if (role !== "super_admin") {
    return <Navigate to="/dashboard" replace />
  }
  return <>{children}</>
}

function ChangePasswordRoute({ children }: { children: React.ReactNode }) {
  const isAuthenticated = authService.isAuthenticated()
  const mustChangePassword = localStorage.getItem("pigate_must_change_password") === "true"

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />
  }
  if (!mustChangePassword) {
    return <Navigate to="/" replace />
  }
  return <>{children}</>
}

export default function App() {
  const [isChecking, setIsChecking] = useState(true)

  useEffect(() => {
    const verifySession = async () => {
      if (!authService.isAuthenticated()) {
        setIsChecking(false)
        return
      }

      try {
        await authService.checkSession()
      } catch (e) {
        console.error("Failed to verify session:", e)
      } finally {
        setIsChecking(false)
      }
    }

    verifySession()
  }, [])

  if (isChecking) {
    return (
      <ThemeProvider defaultTheme="dark" storageKey="pigate-ui-theme">
        <div className="flex min-h-svh flex-col items-center justify-center bg-background text-foreground">
          <div className="flex flex-col items-center space-y-4">
            <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-primary/10 border border-primary/20 text-primary animate-pulse">
              <Shield className="h-6 w-6" />
            </div>
            <div className="flex items-center gap-2 text-sm text-muted-foreground font-medium">
              <Loader2 className="h-4 w-4 animate-spin text-primary" />
              <span>Verifying session...</span>
            </div>
          </div>
        </div>
      </ThemeProvider>
    )
  }

  return (
    <>
      <ThemeProvider defaultTheme="dark" storageKey="pigate-ui-theme">
        <SizeIndicatorSystem />
        <TooltipProvider>
          <AlertDialogProvider>
            <BrowserRouter>

              <Routes>
                {/* Public Login Route */}
                <Route path="/login" element={<Login />} />

                {/* Force change password route */}
                <Route
                  path="/change-password"
                  element={
                    <ChangePasswordRoute>
                      <ForceChangePassword />
                    </ChangePasswordRoute>
                  }
                />

                <Route path="/api-docs" element={<ApiDocs />} />

                {/* Protected Admin Routes under Shell Layout */}
                <Route
                  path="/"
                  element={
                    <ProtectedRoute>
                      <ShellLayout />
                    </ProtectedRoute>
                  }
                >
                  {/* Index route redirects to /dashboard */}
                  <Route index element={<Navigate to="/dashboard" replace />} />

                  <Route path="dashboard" element={<Dashboard />} />

                  {/* Statistics Routes */}
                  <Route path="statistics">
                    <Route index element={<Navigate to="/statistics/overview" replace />} />
                    <Route path="overview" element={<StatisticsOverview />} />
                    <Route path="traffic" element={<StatisticsTraffic />} />
                    <Route path="traffic/host/:ip" element={<StatisticsTrafficHost />} />
                    <Route path="firewall" element={<StatisticsFirewall />} />
                    <Route path="dns" element={<StatisticsDns />} />
                    <Route path="dns/domain/:domain" element={<StatisticsDnsDomain />} />
                    <Route path="dns/client/:client" element={<StatisticsDnsClient />} />
                    <Route path="capacity" element={<StatisticsCapacity />} />
                  </Route>

                  {/* Network Routes */}
                  <Route path="network">
                    <Route path="interfaces" element={<Interfaces />} />
                    <Route path="dns" element={<DNS />} />
                    <Route path="dns-server" element={<DnsServer />} />
                    <Route path="routes" element={<StaticRoutes />} />
                    <Route path="dhcp" element={<DhcpServer />} />
                    <Route path="qos" element={<QoS />} />
                    <Route path="wan" element={<WanFailover />} />
                  </Route>

                  {/* Policy & Objects Routes */}
                  <Route path="policy">
                    <Route path="firewall" element={<FirewallPolicy />} />
                    <Route path="local-in" element={<LocalInPolicy />} />
                    <Route path="local-out" element={<LocalOutPolicy />} />
                    <Route path="port-forwarding" element={<PortForwarding />} />
                    <Route path="addresses" element={<Addresses />} />
                    <Route path="services" element={<Services />} />
                  </Route>

                  {/* Log & Report Routes */}
                  <Route path="logs">
                    <Route path="traffic" element={<ForwardTraffic />} />
                    <Route path="local" element={<LocalTraffic />} />
                    <Route path="events" element={<EventLogs />} />
                    <Route path="statistics" element={<Navigate to="/statistics/overview" replace />} />
                  </Route>

                  {/* System Routes */}
                  <Route path="system">
                    <Route path="settings" element={<SettingsMaintenance />} />
                    <Route
                      path="users"
                      element={
                        <SuperAdminRoute>
                          <Users />
                        </SuperAdminRoute>
                      }
                    />
                  </Route>
                </Route>

                {/* Fallback Catch-All Redirect */}
                <Route path="*" element={<Navigate to="/" replace />} />
              </Routes>
            </BrowserRouter>
          </AlertDialogProvider>
        </TooltipProvider>
      </ThemeProvider>
    </>
  )
}