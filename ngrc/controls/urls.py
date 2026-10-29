from django.urls import path

from . import views as v

urlpatterns = [
    path("controls/common/", v.CommonControlListView.as_view()),
    path("controls/implementation/", v.ImplementationControlListView.as_view()),
    path("controls/implementation/<uuid:pk>/", v.ImplementationControlDetailView.as_view()),
    path("controls/implementation/<uuid:pk>/assert/", v.ImplementationControlAssertView.as_view()),
    path("findings/", v.FindingListView.as_view()),
    path("findings/<uuid:pk>/transition/", v.FindingTransitionView.as_view()),
    path("tasks/", v.TaskListView.as_view()),
    path("tasks/<uuid:pk>/transition/", v.TaskTransitionView.as_view()),
]
