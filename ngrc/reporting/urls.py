from django.urls import path

from . import views as v

urlpatterns = [
    path("reporting/dashboard/", v.DashboardView.as_view()),
    path("reporting/calendar/", v.CalendarView.as_view()),
]
