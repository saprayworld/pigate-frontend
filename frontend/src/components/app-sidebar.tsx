import * as React from "react"
import { NavLink, useLocation } from "react-router"
import {
  LayoutDashboard,
  Network,
  Route as RouteIcon,
  Radio,
  Flame,
  BookOpen,
  Sliders,
  Settings,
  Globe,
  Activity,
  Server,
  Users,
  ScrollText,
  BarChart3,
  ChartColumnBig,
  Gauge,
  ArrowRightLeft,
  ShieldAlert,
  Waypoints,
  LogIn,
  LogOut,
  ChevronRight,
  LineChart,
  ArrowLeftRight,
  Router,
  Shield,
  FileText,
  Cog,
  Shuffle,
} from "lucide-react"

import { NavUser } from "@/components/nav-user"
import { PiGateLogo } from "@/components/PiGateLogo"
import { authService } from "@/services/authService"
import { useHostname } from "@/hooks/useHostname"
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible"
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarMenuSub,
  SidebarMenuSubButton,
  SidebarMenuSubItem,
  useSidebar,
} from "@/components/ui/sidebar"

type NavIcon = React.ComponentType<{ className?: string }>
type NavItem = {
  path: string
  label: string
  icon: NavIcon
  // Opt-in: also treated active when the current path is a sub-route of
  // `path` (e.g. /statistics/dns/domain/:domain highlights the DNS item).
  // Kept opt-in so existing sibling paths never start matching each other.
  matchPrefix?: boolean
}
// A group with a title renders as a FortiGate-style collapsible category row
// (icon required); a group without one (Dashboard) renders as a plain
// top-level link.
type NavGroup = { title?: string; icon?: NavIcon; items: NavItem[] }

function isItemActive(item: NavItem, pathname: string): boolean {
  return (
    pathname === item.path ||
    (item.matchPrefix === true && pathname.startsWith(item.path + "/"))
  )
}

export function AppSidebar({ ...props }: React.ComponentProps<typeof Sidebar>) {
  const location = useLocation()
  const isSuperAdmin = authService.getRole() === "super_admin"
  const { hostname } = useHostname()
  // Close the mobile Sheet after navigating so the destination page is
  // visible right away instead of staying hidden behind the open sidebar.
  const { isMobile, setOpenMobile, state, setOpen } = useSidebar()
  const closeMobileSidebar = () => {
    if (isMobile) setOpenMobile(false)
  }

  // On the icon-only desktop rail, opening a category should temporarily
  // widen the whole sidebar back to normal so its sub-items are readable —
  // then narrow it back to icons once focus leaves the sidebar entirely.
  // Tracked outside React state since it must not itself trigger a render.
  const autoExpandedRef = React.useRef(false)
  const handleCategoryOpenChange = (title: string, open: boolean) => {
    setOpenGroup(open ? title : null)
    if (open && !isMobile && state === "collapsed") {
      autoExpandedRef.current = true
      setOpen(true)
    }
  }
  const handleSidebarBlur = (e: React.FocusEvent<HTMLDivElement>) => {
    if (!autoExpandedRef.current) return
    const next = e.relatedTarget as Node | null
    if (next && e.currentTarget.contains(next)) return
    autoExpandedRef.current = false
    setOpen(false)
  }

  const groups: NavGroup[] = [
    {
      items: [{ path: "/dashboard", label: "Dashboard", icon: LayoutDashboard }],
    },
    {
      title: "Statistics",
      icon: LineChart,
      items: [
        { path: "/statistics/overview", label: "Overview", icon: BarChart3 },
        { path: "/statistics/traffic", label: "Traffic", icon: ArrowLeftRight, matchPrefix: true },
        { path: "/statistics/firewall", label: "Firewall", icon: ShieldAlert, matchPrefix: true },
        { path: "/statistics/dns", label: "DNS", icon: ChartColumnBig, matchPrefix: true },
        { path: "/statistics/capacity", label: "Capacity", icon: Gauge, matchPrefix: true },
      ],
    },
    {
      title: "Network",
      icon: Router,
      items: [
        { path: "/network/interfaces", label: "Interfaces", icon: Network },
        { path: "/network/dns", label: "DNS Settings", icon: Globe },
        { path: "/network/dns-server", label: "DNS Server", icon: Server },
        { path: "/network/routes", label: "Static Routes", icon: RouteIcon },
        { path: "/network/dhcp", label: "DHCP Server", icon: Radio },
        { path: "/network/qos", label: "QoS Limiting", icon: Activity },
        { path: "/network/wan", label: "Multi-WAN", icon: Shuffle },
      ],
    },
    {
      title: "Policy & Objects",
      icon: Shield,
      items: [
        { path: "/policy/firewall", label: "Firewall Policy", icon: Flame },
        { path: "/policy/local-in", label: "Local-In Policy", icon: LogIn },
        { path: "/policy/local-out", label: "Local-Out Policy", icon: LogOut },
        { path: "/policy/port-forwarding", label: "Port Forwarding", icon: Waypoints },
        { path: "/policy/addresses", label: "Addresses", icon: BookOpen },
        { path: "/policy/services", label: "Services", icon: Sliders },
      ],
    },
    {
      title: "Log & Report",
      icon: FileText,
      items: [
        { path: "/logs/traffic", label: "Forward Traffic", icon: ArrowRightLeft },
        { path: "/logs/local", label: "Local Traffic", icon: ShieldAlert },
        { path: "/logs/events", label: "System Events", icon: ScrollText },
      ],
    },
    {
      title: "System",
      icon: Cog,
      items: [
        { path: "/system/settings", label: "Settings & Maintenance", icon: Settings },
        // User Management is super_admin only; the backend enforces access, this
        // just hides an unusable link from read-only admins.
        ...(isSuperAdmin
          ? [{ path: "/system/users", label: "User Management", icon: Users }]
          : []),
      ],
    },
  ]

  // Accordion-style category collapse (FortiGate-like): only one titled group
  // open at a time. Defaults to whichever group contains the current route so
  // landing on a page never hides its own nav item.
  const [openGroup, setOpenGroup] = React.useState<string | null>(() => {
    const activeGroup = groups.find(
      (g) => g.title && g.items.some((item) => isItemActive(item, location.pathname))
    )
    return activeGroup?.title ?? null
  })

  return (
    <Sidebar collapsible="icon" onBlur={handleSidebarBlur} {...props}>
      <SidebarHeader>
        <SidebarMenu>
          <SidebarMenuItem>
            <SidebarMenuButton
              asChild
              className="h-8 data-[slot=sidebar-menu-button]:p-1.5! data-[slot=sidebar-menu-button]:pl-0!"
            >
              <NavLink to="/dashboard" onClick={closeMobileSidebar}>
                <div className="flex aspect-square size-8 items-center justify-center rounded-lg">
                  <PiGateLogo className="shrink-0 h-[28px]! w-[28px]!" />
                </div>
                <div className="grid flex-1 text-left text-xs leading-tight">
                  <span className="truncate text-sm font-bold tracking-wider">PiGate</span>
                  <span className="truncate text-xs text-muted-foreground font-mono">{hostname}</span>
                </div>
              </NavLink>
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarHeader>

      <SidebarContent>
        <SidebarGroup>
          <SidebarGroupContent>
            <SidebarMenu>
              {groups.map((group) => {
                // Ungrouped (Dashboard): a plain top-level link, no accordion.
                if (!group.title) {
                  return group.items.map((item) => {
                    const Icon = item.icon
                    const isActive = isItemActive(item, location.pathname)
                    return (
                      <SidebarMenuItem key={item.path}>
                        <SidebarMenuButton asChild isActive={isActive} tooltip={item.label}>
                          <NavLink to={item.path} onClick={closeMobileSidebar}>
                            <Icon className="size-4" />
                            <span>{item.label}</span>
                          </NavLink>
                        </SidebarMenuButton>
                      </SidebarMenuItem>
                    )
                  })
                }

                const GroupIcon = group.icon
                const hasActiveChild = group.items.some((item) =>
                  isItemActive(item, location.pathname)
                )

                return (
                  <Collapsible
                    key={group.title}
                    asChild
                    open={openGroup === group.title}
                    onOpenChange={(open) => handleCategoryOpenChange(group.title!, open)}
                    className="group/collapsible"
                  >
                    <SidebarMenuItem>
                      <CollapsibleTrigger asChild>
                        <SidebarMenuButton
                          isActive={hasActiveChild}
                          tooltip={group.title}
                          // Expanded sidebar: parent row only tints text (no bg) when a
                          // child is active, even on hover. Icon-only rail: restore the
                          // bg highlight (also under hover), since the collapsed icon
                          // stands in for the active leaf itself.
                          className="data-active:bg-transparent data-active:hover:bg-transparent group-data-[collapsible=icon]:data-active:bg-primary/10! group-data-[collapsible=icon]:data-active:hover:bg-primary/10!"
                        >
                          {GroupIcon && <GroupIcon className="size-4" />}
                          <span className="text-nowrap">{group.title}</span>
                          <ChevronRight className="ml-auto size-4 shrink-0 transition-transform duration-200 group-data-[state=open]/collapsible:rotate-90" />
                        </SidebarMenuButton>
                      </CollapsibleTrigger>
                      <CollapsibleContent>
                        <SidebarMenuSub>
                          {group.items.map((item) => {
                            const isActive = isItemActive(item, location.pathname)
                            return (
                              <SidebarMenuSubItem key={item.path}>
                                <SidebarMenuSubButton asChild isActive={isActive}>
                                  <NavLink to={item.path} onClick={closeMobileSidebar}>
                                    <span>{item.label}</span>
                                  </NavLink>
                                </SidebarMenuSubButton>
                              </SidebarMenuSubItem>
                            )
                          })}
                        </SidebarMenuSub>
                      </CollapsibleContent>
                    </SidebarMenuItem>
                  </Collapsible>
                )
              })}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>
      </SidebarContent>

      <SidebarFooter>
        <NavUser />
      </SidebarFooter>
    </Sidebar>
  )
}
