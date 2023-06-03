from pyexpat.errors import messages
from django.shortcuts import get_object_or_404, render
from django.shortcuts import render,HttpResponse

from django.http import HttpResponse, HttpResponseForbidden, HttpResponseNotFound
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework.views import APIView
from django.http import HttpResponse


from rest_framework import status

from rest_framework import authentication, permissions
from rest_framework.generics import ListAPIView

@api_view(['GET','DELET','ADD'])
def responce(request):
    return HttpResponse('Hello world')
    

from rest_framework.exceptions import AuthenticationFailed
from .serialization import PatSerializer
from .serialization import DrivSerializer
from .serialization import MedSerializer
from .serialization import InferSerializer

from .models import Myuser
import jwt, datetime
from .models import Patient
from .models import Medecine
from .models import Infermier
from .models import Driver

class RegisterView(APIView):
    def post(self, request):
        serializer = PatSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)



class LoginView(APIView):
    def post(self, request):
        email = request.data['email']
        password = request.data['password']

        user = Medecine.objects.filter(email=email).first()

        if user is None:
            raise AuthenticationFailed('User not found!')

        if not user.check_password(password):
            raise AuthenticationFailed('Incorrect password!')

        payload = {
            'id': user.id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=60),
            'iat': datetime.datetime.utcnow()
        }

        token = jwt.encode(payload, 'secret', algorithm='HS256')

        response = Response()

        response.set_cookie(key='jwt', value=token, httponly=True)
        response.data = {
            'jwt': token
        }
        return response
    


class UserView(APIView):

    def get(self, request):
        token = request.COOKIES.get('jwt')

        if not token:
            raise AuthenticationFailed('Unauthenticated!')

        try:
            payload = jwt.decode(token, 'secret', algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Unauthenticated!')

        user = Myuser.objects.filter(id=payload['id']).first()
        serializer = PatSerializer(user)
        return Response(serializer.data)
    


from django.shortcuts import render, redirect
from .models import Patient, Request, Medecine
from django.contrib.auth.decorators import login_required

from .forms import RequestForm



from django.contrib.auth.decorators import login_required

from django.contrib.auth.decorators import login_required, user_passes_test
from django.shortcuts import render, redirect
from .models import Patient, Request, Medecine

@login_required(login_url='/login')
@user_passes_test(lambda u: u.is_superuser)
@login_required(login_url='/login')

def add_request(request, patient_id):
    try:
        patient = Patient.objects.get(pk=patient_id)
    except Patient.DoesNotExist:
        return HttpResponse("Patient not found.", status=404)
    
    SPECIALITES = ['Cardiologue', 'Dermatologue', 'Gynécologue', 'Ophtalmologue', 'Orthopédiste']
    
    if request.method == 'POST':
        # handle form submission
        date = request.POST.get('date')
        time = request.POST.get('time')
        adress = request.POST.get('adress')
        specialite = request.POST.get('specialite')
        # create new request object and save it
        request_obj = Request(patient=patient, requester=patient, date=date, time=time, specialite=specialite,adress=adress)
        request_obj.save()
        return redirect('patient_detail', patient_id=patient_id)
    else:
        # display form to user
        return render(request, 'add_request.html', {'patient': patient, 'SPECIALITES': SPECIALITES})

from django.shortcuts import render, get_object_or_404
from .models import Patient

def patient_detail(request, patient_id):
    patient = get_object_or_404(Patient, pk=patient_id)
    # do something with the patient object
    return render(request, 'patient_detail.html', {'patient': patient})



#CANCEL VIEW

from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect



from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect

@login_required
def cancel_request(request, request_id):
    request_obj = Request.objects.get(pk=request_id)
    if request.user == request_obj.requester:
        request_obj.is_cancelled = True
        request_obj.save()
    return redirect('patient_detail', patient_id=request_obj.patient.id)

from django.shortcuts import render
from django.contrib.auth import authenticate, login

from django.shortcuts import render

from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login

from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from django.views.decorators.csrf import csrf_exempt




from django.shortcuts import render
from django.http import JsonResponse

from django.contrib.auth.hashers import check_password

from django.contrib.auth import authenticate, login
from django.shortcuts import render, redirect
from .models import Administrator

from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from .models import Administrator



from django.contrib.auth.hashers import check_password
from django.shortcuts import redirect, render
from .models import Myuser

from django.contrib.auth import authenticate, login
from django.shortcuts import redirect, render

from .models import Myuser

from django.contrib.auth import authenticate, login
from django.contrib.auth.models import User
from django.shortcuts import render, redirect

from django.contrib.auth import authenticate, login
from django.shortcuts import render, redirect

from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login
from django.shortcuts import render, redirect


from django.shortcuts import render



def show_all_doctors(request):
    doctors = Medecine.objects.all()
    return render(request, 'staff/doctor_list.html', {'doctors': doctors})

from django.shortcuts import render
from .models import Infermier



def nurse_list(request):
    nurses = Infermier.objects.all()
    return render(request, 'staff/nurse_list.html', {'nurses': nurses})

def driver_list(request):
    drivers = Driver.objects.all()
    return render(request, 'staff/driver_list.html', {'drivers': drivers})


from django.shortcuts import render
from .models import Patient

def patient_list(request):
    patients = Patient.objects.all()
    return render(request, 'staff/Menu.html', {'patients': patients})


def add_doctor(request):
    if request.method == 'POST':
        name = request.POST['name']
        prenom = request.POST['prenom']
        email = request.POST['email']
        adress = request.POST['adress']
        spécialité = request.POST['spécialité']
        doctor = Medecine(name=name, prenom=prenom, email=email, adress=adress, spécialité=spécialité)
        doctor.save()
        return redirect('doctor_list')
    return render(request, 'staff/AddDoctor.html')



def add_nurse(request):
    if request.method == 'POST':
        name = request.POST['name']
        prenom = request.POST['prenom']
        email = request.POST['email']
        adress = request.POST['adress']
        
        nurse = Infermier(name=name, prenom=prenom, email=email, adress=adress)
        nurse.save()
        return redirect('nurse_list')
    return render(request, 'staff/AddNurse.html')


def add_driver(request):
    if request.method == 'POST':
        name = request.POST['name']
        prenom = request.POST['prenom']
        email = request.POST['email']
        adress = request.POST['adress']
        
        drive = Driver(name=name, prenom=prenom, email=email, adress=adress)
        drive.save()
        return redirect('driver_list')
    return render(request, 'staff/AddDriver.html')

from django.shortcuts import get_object_or_404, redirect
from .models import Medecine

from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse



from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse



from django.shortcuts import get_object_or_404, render
from .models import Medecine





def show_all_request(request):
    requests = Request.objects.all()
    return render(request, 'request.html', {'requests': requests})


# views.py
from django.shortcuts import render, redirect
from django.contrib.auth import login
from django.contrib.auth.models import User

from django.contrib.auth import authenticate, login
from django.shortcuts import render, redirect
from django.contrib.auth.models import User


from django.contrib.auth import authenticate, login
from django.shortcuts import render, redirect
from django.contrib.auth.hashers import make_password, check_password
def login(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        print('hellooo')

        try:
            user = Myuser.objects.get(email=email)

            if user.check_password(password):
                if user.is_admin:
                    # Successful authentication
                    login(request, user)
                    print('hi')
                    return redirect('Admin_view')
                else:
                    # User is not an admin
                    print('hi2')
                    return render(request, 'login.html', {'error': 'You do not have permission to access the admin area.'})
            else:
                # Invalid credentials
                print('hello3')
                return render(request, 'login.html', {'error': 'Invalid credentials'})
        except Myuser.DoesNotExist:
            # User does not exist
            return render(request, 'login.html', {'error': 'User does not exist'})
    else:
        return render(request, 'login.html')


from django.shortcuts import render

def Admin_view(request):
    return render(request, 'home.html')



def profile_view(request):
    return render(request, 'profile.html')


from django.shortcuts import redirect

def user_login(request):
    return render(request, 'login.html')
    




from django.shortcuts import redirect

def logout_view(request):
    return redirect('login')  # Replace 'login' with the URL name of your login page

from django.shortcuts import render
from django.contrib.auth.decorators import login_required

@login_required
def home_view(request):
    return render(request, 'home.html')


def test(request):
    return render(request, 'test.html')




from django.shortcuts import render, get_object_or_404
from django.http import HttpResponse, JsonResponse
from .models import Medecine

from django.shortcuts import get_object_or_404, HttpResponse
from .models import Medecine
from django.shortcuts import render
from .models import Medecine

def doctors(request):
    doctors = Medecine.objects.all()
    return render(request, 'staff/doctor_list.html', {'doctors': doctors})


def delete_doctor(request, doctor_id):
    doctor = get_object_or_404(Medecine, pk=doctor_id)
    doctor.delete()
    return HttpResponse(status=204)



from django.shortcuts import render, get_object_or_404
from django.http import HttpResponse

from .models import Infermier

def nurses(request):
    nurses = Infermier.objects.all()
    return render(request, 'staff/nurse_list.html', {'nurses': nurses})

def delete_nurse(request, nurse_id):
    nurse = get_object_or_404(Infermier, pk=nurse_id)
    nurse.delete()
    return HttpResponse(status=204)



from django.shortcuts import render, get_object_or_404

def handle_request(request, request_id):
    request_obj = get_object_or_404(Request, id=request_id)  # Assuming you have a Request model
    # Perform your handling logic here
    # You can access the request object and its attributes, such as request_obj.date, request_obj.time, etc.
    # You can also update the request object as needed, e.g., request_obj.status = 'handled'
    return render(request, 'handle_request.html', {'request': request_obj})
