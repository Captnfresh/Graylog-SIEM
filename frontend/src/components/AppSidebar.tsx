import { useEffect, useState } from "react";
import {
  Activity, AlertTriangle, LogIn, Bug, Globe, Eye, Shield,
} from "lucide-react";
import {
  Sidebar,
  SidebarContent,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  useSidebar,
} from "@/components/ui/sidebar";
import RiskGauge from "./RiskGauge";
import { fetchStats, type StatsResponse } from "@/lib/api";

const QUICK_FILTERS = [
  { label: "Failed Logins", icon: LogIn, statKey: "failedLogins" as const, query: "Show failed login attempts" },
  { label: "Errors",        icon: Bug,   statKey: "errors" as const,        query: "Show recent errors" },
  { label: "Network",       icon: Globe, statKey: "networkActivity" as const, query: "Show network activity" },
  { label: "Suspicious",    icon: Eye,   statKey: "suspiciousBehaviour" as const, query: "Show suspicious behaviour" },
];

interface AppSidebarProps {
  onQuickFilter: (query: string) => void;
}

const AppSidebar = ({ onQuickFilter }: AppSidebarProps) => {
  const { state } = useSidebar();
  const collapsed = state === "collapsed";
  const [stats, setStats] = useState<StatsResponse | null>(null);

  useEffect(() => {
    fetchStats().then(setStats).catch(() => {/* backend not yet up */});
    const id = setInterval(() => {
      fetchStats().then(setStats).catch(() => {});
    }, 30_000);
    return () => clearInterval(id);
  }, []);

  return (
    <Sidebar collapsible="icon" className="border-r border-border">
      <SidebarContent className="bg-sidebar">
        {/* System Status */}
        <SidebarGroup>
          <SidebarGroupLabel className="text-xs font-mono text-muted-foreground tracking-wider">
            {!collapsed && "SYSTEM STATUS"}
          </SidebarGroupLabel>
          <SidebarGroupContent>
            {!collapsed && (
              <div className="px-3 space-y-4 py-2">
                <div className="flex items-center gap-2">
                  <div className="h-2 w-2 rounded-full bg-accent animate-pulse-glow" />
                  <span className="text-sm text-accent font-mono">ACTIVE — MONITORING</span>
                </div>
                <RiskGauge score={stats?.riskScore ?? 0} />
                <div className="flex items-center justify-between p-2 rounded-md bg-muted/50 border border-border">
                  <div className="flex items-center gap-2">
                    <AlertTriangle className="h-4 w-4 text-warning" />
                    <span className="text-xs text-muted-foreground">Active Alerts</span>
                  </div>
                  <span className="text-sm font-bold font-mono text-warning">
                    {stats?.activeAlerts ?? "—"}
                  </span>
                </div>
              </div>
            )}
            {collapsed && (
              <div className="flex flex-col items-center gap-3 py-2">
                <div className="h-2 w-2 rounded-full bg-accent animate-pulse-glow" />
                <Activity className="h-4 w-4 text-primary" />
              </div>
            )}
          </SidebarGroupContent>
        </SidebarGroup>

        {/* Quick Filters */}
        <SidebarGroup>
          <SidebarGroupLabel className="text-xs font-mono text-muted-foreground tracking-wider">
            {!collapsed && "QUICK FILTERS"}
          </SidebarGroupLabel>
          <SidebarGroupContent>
            <SidebarMenu>
              {QUICK_FILTERS.map((item) => (
                <SidebarMenuItem key={item.label}>
                  <SidebarMenuButton
                    onClick={() => onQuickFilter(item.query)}
                    className="hover:bg-primary/10 hover:text-primary transition-colors"
                  >
                    <item.icon className="h-4 w-4" />
                    {!collapsed && (
                      <div className="flex items-center justify-between flex-1">
                        <span className="text-sm">{item.label}</span>
                        <span className="text-xs font-mono text-muted-foreground bg-muted px-1.5 py-0.5 rounded">
                          {stats ? stats[item.statKey] : "—"}
                        </span>
                      </div>
                    )}
                  </SidebarMenuButton>
                </SidebarMenuItem>
              ))}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>

        {/* Footer */}
        {!collapsed && (
          <div className="mt-auto p-4 border-t border-border">
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <Shield className="h-3 w-3" />
              <span className="font-mono">OmniLog v1.0</span>
            </div>
          </div>
        )}
      </SidebarContent>
    </Sidebar>
  );
};

export default AppSidebar;
