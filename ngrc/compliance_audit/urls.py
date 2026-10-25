from django.urls import path

from . import views as v

urlpatterns = [
    path("audits/", v.AuditListView.as_view()),
    path("audits/<uuid:pk>/", v.AuditDetailView.as_view()),
    path("audits/<uuid:pk>/transition/", v.AuditTransitionView.as_view()),
    path("audits/<uuid:pk>/items/", v.AuditItemListView.as_view()),
]
