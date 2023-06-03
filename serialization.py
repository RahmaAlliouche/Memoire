from pyexpat import model
from rest_framework.serializers import ModelSerializer
from .models import Medecine
from .models import Rapport
from .models import Patient
from rest_framework import serializers
from rest_framework.response import Response
from rest_framework.decorators import api_view
from .models import Dossier_medecale

from .models import Myuser
from .models import Infermier
from .models import Driver

class PatSerializer(serializers.ModelSerializer):
    class Meta:
        model = Patient
        fields = [ 'name','prenom', 'email', 'password','adress']
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def create(self, validated_data):
        password = validated_data.pop('password', None)
        instance = self.Meta.model(**validated_data)
        if password is not None:
            instance.set_password(password)
        instance.save()
        return instance

class MedSerializer(serializers.ModelSerializer):
    class Meta:
        model = Medecine
        fields = [ 'name','prenom','email', 'password','adress','spécialité']
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def create(self, validated_data):
        password = validated_data.pop('password', None)
        instance = self.Meta.model(**validated_data)
        if password is not None:
            instance.set_password(password)
        instance.save()
        return instance

class InferSerializer(serializers.ModelSerializer):
    class Meta:
        model = Infermier
        fields = [ 'name','prenom','email', 'password']
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def create(self, validated_data):
        password = validated_data.pop('password', None)
        instance = self.Meta.model(**validated_data)
        if password is not None:
            instance.set_password(password)
        instance.save()
        return instance


class DrivSerializer(serializers.ModelSerializer):
    class Meta:
        model = Driver
        fields = [ 'name','email', 'password']
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def create(self, validated_data):
        password = validated_data.pop('password', None)
        instance = self.Meta.model(**validated_data)
        if password is not None:
            instance.set_password(password)
        instance.save()
        return instance