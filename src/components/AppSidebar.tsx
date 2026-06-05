import { Link, useRouterState } from "@tanstack/react-router";
import {
  Activity,
  Network,
  Gauge,
  FileText,
  ShieldCheck,
  GitBranch,
  Workflow,
  ScrollText,
  Wrench,
  Share2,
} from "lucide-react";
import {
  Sidebar,
  SidebarContent,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarFooter,
} from "@/components/ui/sidebar";

const operations = [
  { title: "Dashboard & Triage", url: "/", icon: Activity },
  { title: "Force Graph", url: "/graph", icon: Share2 },
  { title: "Evidence Graph", url: "/evidence", icon: Network },
  { title: "Architecture & Timeline", url: "/architecture", icon: Workflow },
];

const investigations = [
  { title: "MITRE ATT&CK", url: "/mitre", icon: GitBranch },
  { title: "Audit Log Stream", url: "/audit", icon: ScrollText },
  { title: "Tools & CLI", url: "/tools", icon: Wrench },
];

const reporting = [
  { title: "Accuracy Benchmark", url: "/benchmark", icon: Gauge },
  { title: "Forensic Report", url: "/report", icon: FileText },
];

export function AppSidebar() {
  const currentPath = useRouterState({ select: (r) => r.location.pathname });
  const isActive = (p: string) => (p === "/" ? currentPath === "/" : currentPath.startsWith(p));

  return (
    <Sidebar collapsible="icon">
      <SidebarHeader className="border-b border-sidebar-border">
        <div className="flex items-center gap-2 px-2 py-3">
          <div className="flex h-8 w-8 items-center justify-center rounded-md bg-confirmed/15 ring-1 ring-confirmed/40">
            <ShieldCheck className="h-4 w-4 text-confirmed" />
          </div>
          <div className="flex flex-col leading-tight group-data-[collapsible=icon]:hidden">
            <span className="font-mono text-sm font-semibold tracking-wider text-foreground">
              ProofSIFT
            </span>
            <span className="text-[10px] uppercase tracking-[0.18em] text-muted-foreground">
              DFIR Control Room
            </span>
          </div>
        </div>
      </SidebarHeader>
      <SidebarContent>
        {[
          { label: "Operations", items: operations },
          { label: "Investigations", items: investigations },
          { label: "Reporting", items: reporting },
        ].map((g) => (
          <SidebarGroup key={g.label}>
            <SidebarGroupLabel>{g.label}</SidebarGroupLabel>
            <SidebarGroupContent>
              <SidebarMenu>
                {g.items.map((item) => (
                  <SidebarMenuItem key={item.url}>
                    <SidebarMenuButton asChild isActive={isActive(item.url)} tooltip={item.title}>
                      <Link to={item.url} className="flex items-center gap-2">
                        <item.icon className="h-4 w-4" />
                        <span>{item.title}</span>
                      </Link>
                    </SidebarMenuButton>
                  </SidebarMenuItem>
                ))}
              </SidebarMenu>
            </SidebarGroupContent>
          </SidebarGroup>
        ))}
      </SidebarContent>
      <SidebarFooter className="border-t border-sidebar-border">
        <div className="px-2 py-2 text-[10px] font-mono uppercase tracking-widest text-muted-foreground group-data-[collapsible=icon]:hidden">
          <div className="flex items-center gap-2">
            <span className="h-1.5 w-1.5 rounded-full bg-confirmed animate-pulse" />
            case proofsift-demo-001
          </div>
        </div>
      </SidebarFooter>
    </Sidebar>
  );
}
