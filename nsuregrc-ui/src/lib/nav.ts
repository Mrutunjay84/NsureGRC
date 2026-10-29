import {
  LayoutDashboard,
  ShieldCheck,
  FileStack,
  FileWarning,
  CheckSquare,
  ShieldAlert,
  Scale,
  ClipboardCheck,
  Lock,
  Building2,
  Server,
  CalendarClock,
  type LucideIcon,
} from "lucide-react";

export interface NavItem {
  label: string;
  path: string;
  icon: LucideIcon;
}

export interface NavSection {
  label: string;
  items: NavItem[];
}

// Grouped to mirror 09_UI_UX.md's structure, scoped to what's actually built - no "coming soon" entries.
export const NAV_SECTIONS: NavSection[] = [
  {
    label: "Overview",
    items: [
      { label: "Dashboard", path: "/", icon: LayoutDashboard },
      { label: "Calendar", path: "/calendar", icon: CalendarClock },
    ],
  },
  {
    label: "Operations",
    items: [
      { label: "Controls", path: "/controls", icon: ShieldCheck },
      { label: "Evidence", path: "/evidence", icon: FileStack },
      { label: "Tasks", path: "/tasks", icon: CheckSquare },
    ],
  },
  {
    label: "Governance",
    items: [
      { label: "Findings", path: "/findings", icon: FileWarning },
      { label: "Policies & Objectives", path: "/governance", icon: Scale },
    ],
  },
  {
    label: "Risk",
    items: [
      { label: "Risk Register", path: "/risk", icon: ShieldAlert },
      { label: "Assets & Incidents", path: "/assets", icon: Server },
    ],
  },
  {
    label: "Compliance",
    items: [{ label: "Audits", path: "/audits", icon: ClipboardCheck }],
  },
  {
    label: "Privacy",
    items: [{ label: "Privacy", path: "/privacy", icon: Lock }],
  },
  {
    label: "Third Parties",
    items: [{ label: "Third Parties", path: "/third-parties", icon: Building2 }],
  },
];
