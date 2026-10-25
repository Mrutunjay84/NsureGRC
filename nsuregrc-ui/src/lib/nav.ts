import {
  LayoutDashboard,
  ShieldCheck,
  FileStack,
  FileWarning,
  CheckSquare,
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
    items: [{ label: "Dashboard", path: "/", icon: LayoutDashboard }],
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
    items: [{ label: "Findings", path: "/findings", icon: FileWarning }],
  },
  // Risk, Policies & Objectives (governance), Audits, Privacy sections come back here as each page lands
  // (see App.tsx's own note) - their REST APIs already exist, the nav entry follows the page, not ahead of it.
];
