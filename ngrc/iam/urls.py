from django.urls import path

from . import views as v

urlpatterns = [
    path("csrf/", v.CsrfView.as_view()),
    path("login/", v.LoginView.as_view()),
    path("logout/", v.LogoutView.as_view()),
    path("session/", v.SessionView.as_view()),
    path("mfa/totp/verify/", v.TotpVerifyView.as_view()),
    path("mfa/recovery/verify/", v.RecoveryVerifyView.as_view()),
    path("mfa/webauthn/authenticate/begin/", v.WebAuthnAuthBeginView.as_view()),
    path("mfa/webauthn/authenticate/complete/", v.WebAuthnAuthCompleteView.as_view()),
    path("mfa/totp/enroll/begin/", v.TotpEnrollBeginView.as_view()),
    path("mfa/totp/enroll/confirm/", v.TotpEnrollConfirmView.as_view()),
    path("mfa/webauthn/register/begin/", v.WebAuthnRegisterBeginView.as_view()),
    path("mfa/webauthn/register/complete/", v.WebAuthnRegisterCompleteView.as_view()),
    path("tenants/", v.TenantsView.as_view()),
    path("tenants/select/", v.SelectTenantView.as_view()),
    path("stepup/", v.StepUpView.as_view()),
    path("stepup/webauthn/begin/", v.StepUpWebAuthnBeginView.as_view()),
    path("stepup/webauthn/complete/", v.StepUpWebAuthnCompleteView.as_view()),
    path("password/change/", v.PasswordChangeView.as_view()),
    path("password/reset/request/", v.ResetRequestView.as_view()),
    path("password/reset/confirm/", v.ResetConfirmView.as_view()),
    path("email/verify/", v.VerifyEmailView.as_view()),
    path("invitations/accept/", v.AcceptInvitationView.as_view()),
]
