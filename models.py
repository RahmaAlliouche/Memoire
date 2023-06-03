from django.db import models
from collections import UserList
from django.contrib.auth.hashers import make_password
from django.contrib.auth.hashers import check_password

class Myuser(models.Model):

    email = models.CharField(max_length=255, unique=True)
    password = models.CharField(max_length=255)
    is_admin= models.BooleanField(default=True)
    
    

    def set_password(self, raw_password):
       self.password = make_password(raw_password)


    def check_password(self, raw_password):
        return check_password(raw_password, self.password)





class Medecine(models.Model):
    name=models.CharField(max_length=255)
    prenom=models.CharField(max_length=255)
    image=models.ImageField(upload_to='photo')
    email=models.CharField(max_length=50,unique=True)
    adress=models.CharField(max_length=255)
    password=models.CharField(max_length=8)
    phone=models.IntegerField
    spécialité=models.CharField(max_length=255)
    
    def set_password(self, raw_password):


        self.password = make_password(raw_password)

    def check_password(self, raw_password):
        return check_password(raw_password, self.password)



class Infermier(models.Model):
    name=models.CharField(max_length=255)
    prenom=models.CharField(max_length=255)
    image=models.ImageField(upload_to='photo')
    email=models.CharField(max_length=255)
    adress=models.CharField(max_length=255)
    password=models.CharField(max_length=8)
    phone=models.IntegerField
    def set_password(self, raw_password):


        self.password = make_password(raw_password)

    def check_password(self, raw_password):
        return check_password(raw_password, self.password)

from datetime import date



class Patient(models.Model):
    name=models.CharField(max_length=255)
    prenom=models.CharField(max_length=255)
    email=models.CharField(max_length=255)
    adress=models.CharField(max_length=255)
    password=models.CharField(max_length=8)
    num_téle=models.IntegerField
    
    def set_password(self, raw_password):


        self.password = make_password(raw_password)

    def check_password(self, raw_password):
        return check_password(raw_password, self.password)


class Driver(models.Model):
    name=models.CharField(max_length=255)
    prenom=models.CharField(max_length=255)
    image=models.ImageField(upload_to='photo')
    email=models.CharField(max_length=255)
    adress=models.CharField(max_length=255)
    password=models.CharField(max_length=8)
    def set_password(self, raw_password):


        self.password = make_password(raw_password)

    def check_password(self, raw_password):
        return check_password(raw_password, self.password)



class Rapport(models.Model):
    text=models.FileField(upload_to='photo')
    medecine=models.ForeignKey(Medecine,on_delete=models.CASCADE,related_name='rapport')
    nurse=models.ForeignKey(Infermier,on_delete=models.CASCADE,related_name='rapport')
    patient=models.ForeignKey(Patient,on_delete=models.CASCADE,related_name='rapport')


class Dossier_medecale(models.Model):
    text=models.FileField(upload_to='photo')
    patient=models.ForeignKey(Patient,on_delete=models.CASCADE,related_name='dossier_medecale')
    medecine=models.ForeignKey(Medecine,on_delete=models.CASCADE,related_name='dossier_medecale')
    rapport=models.ForeignKey(Rapport,on_delete=models.CASCADE,related_name='dossier_medecale') 


class Planing(models.Model):
    ref=models.ImageField(upload_to='photo')
    medecine=models.ForeignKey(Medecine,on_delete=models.CASCADE,related_name='planning')
    nurse=models.ForeignKey(Infermier,on_delete=models.CASCADE,related_name='planning')
    driver=models.ForeignKey(Driver,on_delete=models.CASCADE,related_name='planning')


class Abcense(models.Model):
    date=models.DateField
    time=models.TimeField
    raison=models.CharField(max_length=500)
    medecine=models.ForeignKey(Medecine,on_delete=models.CASCADE,related_name='abcense')
    nurse=models.ForeignKey(Infermier,on_delete=models.CASCADE,related_name='abcense')


class Administrator(models.Model):
    name=models.CharField(max_length=50)
    prenom=models.CharField(max_length=50)
    email=models.CharField(max_length=50)
    adress=models.CharField(max_length=50)
    password=models.CharField(max_length=8)
    def authenticate(self, password):
        if check_password(password, self.password):
            return self
        return None
    



from datetime import date

class Request(models.Model):
    patient = models.ForeignKey(Patient, on_delete=models.CASCADE)
    date = models.DateField()
    time = models.TimeField()
    adress=models.CharField(max_length=100,default='')
    requester = models.ForeignKey(Patient, on_delete=models.CASCADE, related_name='requested_requests', null=True, default=None)
    created_at = models.DateTimeField(auto_now_add=True)
    is_cancelled = models.BooleanField(default=False)
    specialite = models.CharField(max_length=255, blank=True)
    medic = models.ForeignKey(Medecine, on_delete=models.SET_NULL, null=True, blank=True)

    def __str__(self):
        return f"Request for {self.patient} "



