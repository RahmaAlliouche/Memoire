from django.contrib import admin

# Register your models here.
from .models import Myuser
from .models import Medecine
from .models import Infermier
from .models import Patient
from .models import Planing
from .models import Abcense
from .models import Dossier_medecale
from .models import Rapport
from .models import Driver

from .models import Request

admin.site.site_header = "Administrator"  # Change the name displayed in the header
admin.site.site_title = "Administrator"   # Change the name displayed in the browser title


admin.site.register(Myuser)


admin.site.register(Patient)
admin.site.register(Planing)
admin.site.register(Abcense)
admin.site.register(Dossier_medecale)
admin.site.register(Rapport)


admin.site.register(Request)

@admin.register(Medecine)

class Medecine(admin.ModelAdmin):
    list_display = ("name", "prenom","spécialité")

@admin.register(Driver)

class Driver(admin.ModelAdmin):
    list_display = ("name", "email")

@admin.register(Infermier)

class Nurse(admin.ModelAdmin):
    list_display = ("name", "prenom","email")
