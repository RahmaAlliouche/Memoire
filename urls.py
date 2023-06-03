from django.urls import path
from . import views
from .views import RegisterView, delete_nurse, driver_list, nurse_list, nurses, patient_list, test
from .views import LoginView
from .views import UserView
from .views import show_all_doctors

from .views import patient_detail
from .views import Admin_view
from .views import user_login
from .views import logout_view
from .views import home_view

from .views import doctors
from .views import delete_doctor



urlpatterns = [
    
    path('',views.responce),
    path('api/register/', RegisterView.as_view()),
    path('login/', LoginView.as_view()),
    path('user/', UserView.as_view()),
    #path('up/',views.signUp),
    path('patient/<int:patient_id>/request/add/', views.add_request, name='add_request'),
    path('request/<int:request_id>/cancel/', views.cancel_request, name='cancel_request'),
    path('patient/<int:patient_id>/', patient_detail, name='patient_detail'),
    #path('log/', views.login, name='login'),
    
    path('admine/doctors/', views.show_all_doctors,name='doctor_list'),
    path('admine/nurse/', views.nurse_list, name='nurse_list'),
    
    path('admine/driver/', views.driver_list, name='driver_list'),
    path('admine/pat/', views.patient_list, name='Menu'),
    path('add_doctor/', views.add_doctor, name='add_doctor'),
    path('add_nurse/', views.add_nurse, name='add_nurse'),
    path('add_driver/', views.add_driver, name='add_driver'),
    path('admine/requests/', views.show_all_request, name='request'),
    path('logine/', views.user_login,name='login'),
    path('logine/submit', views.login,name='submit_form'),

    path('admine/', Admin_view,name='Admin_view'),
    path('admine/profile.html', views.profile_view, name='profile'),
    path('logout/', logout_view, name='logout'),
    #path('logine/home/', home_view, name='home'),
    #path('test/', test),
    path('doctors/', doctors, name='doctors'),
    path('delete-doctor/<int:doctor_id>/', delete_doctor, name='delete_doctor'),
    path('nurses/', nurses, name='nurses'),
    path('delete-nurse/<int:nurse_id>/', delete_nurse, name='delete_nurse'),
    path('handle-request/<int:request_id>/', views.handle_request, name='handle_request'),
]
   




    
  
