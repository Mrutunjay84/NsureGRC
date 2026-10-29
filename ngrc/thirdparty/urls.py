from django.urls import path

from . import views as v

urlpatterns = [
    path("third-parties/entities/", v.EntityListView.as_view()),
    path("third-parties/entities/<uuid:pk>/", v.EntityDetailView.as_view()),
    path("third-parties/representatives/", v.RepresentativeListView.as_view()),
    path("third-parties/solutions/", v.SolutionListView.as_view()),
    path("third-parties/assessments/", v.AssessmentListView.as_view()),
    path("third-parties/assessments/<uuid:pk>/transition/", v.AssessmentTransitionView.as_view()),
]
