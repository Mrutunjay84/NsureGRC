from django.urls import path

from . import views as v

urlpatterns = [
    path("me/", v.MeView.as_view()),
    path("roles/", v.RoleListView.as_view()),
    path("roles/<uuid:pk>/", v.RoleDetailView.as_view()),
    path("members/", v.MemberListView.as_view()),
    path("members/<uuid:pk>/", v.MemberDetailView.as_view()),
    path("invitations/", v.InvitationListView.as_view()),
    path("invitations/<uuid:pk>/", v.InvitationDetailView.as_view()),
    path("support/grants/", v.SupportGrantListView.as_view()),
    path("support/grants/<uuid:pk>/consent/", v.SupportConsentView.as_view()),
    path("support/grants/<uuid:pk>/deny/", v.SupportDenyView.as_view()),
    path("support/grants/<uuid:pk>/revoke/", v.SupportRevokeView.as_view()),
    path("recovery/", v.RecoveryListView.as_view()),
    path("recovery/<uuid:pk>/approve/", v.RecoveryApproveView.as_view()),
    path("recovery/<uuid:pk>/deny/", v.RecoveryDenyView.as_view()),
    path("audit/events/", v.AuditEventsView.as_view()),
    path("audit/export/", v.AuditExportView.as_view()),
]
