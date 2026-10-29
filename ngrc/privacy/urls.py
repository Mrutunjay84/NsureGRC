from django.urls import path

from . import views as v

urlpatterns = [
    path("privacy/processing-activities/", v.ProcessingActivityListView.as_view()),
    path("privacy/rights-requests/", v.RightsRequestListView.as_view()),
    path("privacy/rights-requests/<uuid:pk>/transition/", v.RightsRequestTransitionView.as_view()),
    path("privacy/breaches/", v.BreachListView.as_view()),
    path("privacy/breaches/<uuid:pk>/transition/", v.BreachTransitionView.as_view()),
]
