from django.urls import path

from . import views as v

urlpatterns = [
    path("risk/assessments/", v.RiskAssessmentListView.as_view()),
    path("risk/scenarios/", v.RiskScenarioListView.as_view()),
    path("risk/scenarios/<uuid:pk>/transition/", v.RiskScenarioTransitionView.as_view()),
]
