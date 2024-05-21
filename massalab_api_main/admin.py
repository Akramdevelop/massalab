from django.contrib import admin
from .models import order, DoctorProfile, UserProfile, LaboratoryProfile, Contract, OrderRecords

admin.site.register(order)
admin.site.register(OrderRecords)
admin.site.register(DoctorProfile)
admin.site.register(UserProfile)
admin.site.register(LaboratoryProfile)
admin.site.register(Contract)
