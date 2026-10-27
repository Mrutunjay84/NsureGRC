import { useEffect, useState } from "react";
import { LoginPage } from "@/pages/LoginPage";
import { DashboardPage } from "@/pages/DashboardPage";
import { api } from "@/lib/api";
import type { SessionResponse } from "@/lib/api";

type AuthState = "checking" | "signed_out" | "signed_in";

function App() {
  const [auth, setAuth] = useState<AuthState>("checking");

  useEffect(() => {
    api
      .get<SessionResponse>("/auth/session/")
      .then((s) => setAuth(s.stage === "active" && s.tenant_id ? "signed_in" : "signed_out"))
      .catch(() => setAuth("signed_out"));
  }, []);

  if (auth === "checking") return null;
  if (auth === "signed_in") return <DashboardPage onLoggedOut={() => setAuth("signed_out")} />;
  return <LoginPage onReady={() => setAuth("signed_in")} />;
}

export default App;
