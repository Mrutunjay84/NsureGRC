import { NavLink, Outlet } from "react-router-dom";
import { LogOut, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { NAV_SECTIONS } from "@/lib/nav";
import { api } from "@/lib/api";

export function AppShell({ onLoggedOut, accountEmail }: { onLoggedOut: () => void; accountEmail: string }) {
  async function logout() {
    await api.post("/auth/logout/");
    onLoggedOut();
  }

  return (
    <div className="flex min-h-svh bg-background">
      <aside className="flex w-64 shrink-0 flex-col border-r bg-sidebar text-sidebar-foreground">
        <div className="flex items-center gap-2 border-b border-sidebar-border px-5 py-4">
          <ShieldCheck className="h-5 w-5 text-sidebar-primary" />
          <span className="text-sm font-semibold tracking-tight">NsureGRC</span>
        </div>
        <nav className="flex-1 space-y-5 overflow-y-auto px-3 py-4">
          {NAV_SECTIONS.map((section) => (
            <div key={section.label}>
              <p className="px-2 pb-1 text-[11px] font-medium uppercase tracking-wider text-sidebar-foreground/50">
                {section.label}
              </p>
              <div className="space-y-0.5">
                {section.items.map((item) => (
                  <NavLink
                    key={item.path}
                    to={item.path}
                    end={item.path === "/"}
                    className={({ isActive }) =>
                      `flex items-center gap-2.5 rounded-md px-2.5 py-1.5 text-sm transition-colors ${
                        isActive
                          ? "bg-sidebar-accent text-sidebar-accent-foreground font-medium"
                          : "text-sidebar-foreground/80 hover:bg-sidebar-accent/60 hover:text-sidebar-accent-foreground"
                      }`
                    }
                  >
                    <item.icon className="h-4 w-4 shrink-0" />
                    {item.label}
                  </NavLink>
                ))}
              </div>
            </div>
          ))}
        </nav>
        <div className="border-t border-sidebar-border px-3 py-3">
          <div className="flex items-center justify-between gap-2 px-2">
            <span className="truncate text-xs text-sidebar-foreground/70">{accountEmail}</span>
            <Button variant="ghost" size="icon-sm" onClick={() => void logout()} aria-label="Log out">
              <LogOut className="h-4 w-4" />
            </Button>
          </div>
        </div>
      </aside>
      <main className="min-w-0 flex-1 overflow-y-auto">
        <Outlet />
      </main>
    </div>
  );
}
