from django.urls import path

from . import views as v

urlpatterns = [
    path("governance/policies/", v.PolicyListView.as_view()),
    path("governance/objectives/", v.ObjectiveListView.as_view()),
    path("governance/issues/", v.IssueListView.as_view()),
    path("governance/issues/<uuid:pk>/transition/", v.IssueTransitionView.as_view()),
]
