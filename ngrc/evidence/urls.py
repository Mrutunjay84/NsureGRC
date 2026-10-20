from django.urls import path

from . import views as v

urlpatterns = [
    path("evidence/", v.EvidenceListView.as_view()),
    path("evidence/<uuid:pk>/", v.EvidenceDetailView.as_view()),
    path("evidence/<uuid:pk>/revisions/", v.RevisionUploadView.as_view()),
    path("evidence/<uuid:pk>/revisions/<uuid:rid>/download/", v.RevisionDownloadView.as_view()),
    path("search/", v.SearchView.as_view()),
]
