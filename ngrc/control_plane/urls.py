from django.urls import path

from . import views as v

urlpatterns = [
    path("auth/csrf/", v.CsrfView.as_view()),
    path("auth/login/", v.LoginView.as_view()),
    path("auth/logout/", v.LogoutView.as_view()),
    path("auth/session/", v.SessionView.as_view()),
    path("auth/mfa/webauthn/register/begin/", v.WebAuthnRegisterBeginView.as_view()),
    path("auth/mfa/webauthn/register/complete/", v.WebAuthnRegisterCompleteView.as_view()),
    path("auth/mfa/webauthn/authenticate/begin/", v.WebAuthnAuthBeginView.as_view()),
    path("auth/mfa/webauthn/authenticate/complete/", v.WebAuthnAuthCompleteView.as_view()),
    path("auth/stepup/webauthn/begin/", v.StepUpBeginView.as_view()),
    path("auth/stepup/webauthn/complete/", v.StepUpCompleteView.as_view()),
    path("tenants/", v.TenantListView.as_view()),
    path("support/grants/", v.GrantListView.as_view()),
    path("support/grants/<uuid:pk>/approve/begin/", v.GrantApproveBeginView.as_view()),
    path("support/grants/<uuid:pk>/approve/", v.GrantApproveView.as_view()),
    path("support/grants/<uuid:pk>/activate/", v.GrantActivateView.as_view()),
    path("support/grants/<uuid:pk>/start/", v.SupportSessionStartView.as_view()),
    path("support/session/end/", v.SupportSessionEndView.as_view()),
    path("support/tenant/diagnostics/", v.TenantDiagnosticsView.as_view()),
    path("support/tenant/roles/", v.TenantRolesView.as_view()),
    path("audit/platform/", v.PlatformAuditView.as_view()),
]
