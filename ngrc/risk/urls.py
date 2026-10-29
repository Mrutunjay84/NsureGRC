from django.urls import path

from . import views as v

urlpatterns = [
    path("risk/assessments/", v.RiskAssessmentListView.as_view()),
    path("risk/scenarios/", v.RiskScenarioListView.as_view()),
    path("risk/scenarios/<uuid:pk>/transition/", v.RiskScenarioTransitionView.as_view()),
    path("risk/incidents/", v.IncidentListView.as_view()),
    path("risk/incidents/<uuid:pk>/transition/", v.IncidentTransitionView.as_view()),
    path("assets/", v.AssetListView.as_view()),
    path("assets/<uuid:pk>/", v.AssetDetailView.as_view()),
    path("assets/bia/", v.AssetBiaListView.as_view()),
]
