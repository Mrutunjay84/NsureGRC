import { useEffect, useState } from "react";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { LoginPage } from "@/pages/LoginPage";
import { DashboardPage } from "@/pages/DashboardPage";
import { ControlsPage } from "@/pages/ControlsPage";
import { ControlDetailPage } from "@/pages/ControlDetailPage";
import { EvidencePage } from "@/pages/EvidencePage";
import { FindingsPage } from "@/pages/FindingsPage";
import { TasksPage } from "@/pages/TasksPage";
// Risk/Governance/Audits/Privacy pages: their REST APIs are already built (ngrc.risk/governance/
// compliance_audit/privacy), but the pages themselves are each a separate, independent increment -
// added back here one at a time as each lands, not stubbed in ahead of the page that uses them.
import { AppShell } from "@/components/layout/AppShell";
import { api } from "@/lib/api";
import type { SessionResponse } from "@/lib/api";

type AuthState = { status: "checking" } | { status: "signed_out" } | { status: "signed_in"; email: string };

function App() {
  const [auth, setAuth] = useState<AuthState>({ status: "checking" });

  useEffect(() => {
    api
      .get<SessionResponse>("/auth/session/")
      .then((s) =>
        setAuth(
          s.stage === "active" && s.tenant_id ? { status: "signed_in", email: s.account.email } : { status: "signed_out" },
        ),
      )
      .catch(() => setAuth({ status: "signed_out" }));
  }, []);

  if (auth.status === "checking") return null;

  if (auth.status === "signed_out") {
    return <LoginPage onReady={() => window.location.reload()} />;
  }

  return (
    <BrowserRouter>
      <Routes>
        <Route element={<AppShell onLoggedOut={() => setAuth({ status: "signed_out" })} accountEmail={auth.email} />}>
          <Route path="/" element={<DashboardPage />} />
          <Route path="/controls" element={<ControlsPage />} />
          <Route path="/controls/:id" element={<ControlDetailPage />} />
          <Route path="/evidence" element={<EvidencePage />} />
          <Route path="/findings" element={<FindingsPage />} />
          <Route path="/tasks" element={<TasksPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}

export default App;
