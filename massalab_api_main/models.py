from datetime import timedelta
from django.utils import timezone
from django.db import models
from django.contrib.auth.models import User
from phonenumber_field.modelfields import PhoneNumberField

class UserProfile(models.Model):
    DOCTOR = 'd'
    LABORATORY = 'l'
    DELIVERY = 'e'
    NORMAL = 'n'

    ROLE_CHOICES = [
        (DOCTOR, 'Doctor'),
        (LABORATORY, 'Laboratory'),
        (DELIVERY, 'Delivery'),
        (NORMAL, 'Normal'),
    ]

    user = models.OneToOneField(User, on_delete=models.CASCADE)
    role = models.CharField(max_length=1, choices=ROLE_CHOICES, default=NORMAL)
    phoneNumber = PhoneNumberField(null=True, blank=True, unique=True)
    address = models.CharField(null=True, blank=True)
    building_nbr = models.CharField(null=True, blank=True)
    floor_nbr = models.CharField(null=True, blank=True)
    # is_subscribed = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True, null=True, blank=True)
    # set subscription_expiry to 7 days after the registration date by defult
    subscription_expiry = models.DateTimeField(null=True, blank=True)

    def save(self, *args, **kwargs):
        if not self.subscription_expiry:
            self.subscription_expiry = timezone.now() + timedelta(days=7)
        super().save(*args, **kwargs)


class LaboratoryProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    name = models.CharField(max_length=255)
    # location = gisModels.PointField(null=True, blank=True)
    issubscribed = models.BooleanField(default=False)
    # subscription_expiry = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return self.name


class DoctorProfile(models.Model):
    user = models.OneToOneField(
        User, on_delete=models.CASCADE)
    name = models.CharField(max_length=255, null=True)
    laboratory = models.ForeignKey(
        LaboratoryProfile, on_delete=models.CASCADE, related_name='doctors', null=True, blank=True)
    # location = gisModels.PointField(null=True, blank=True)
    is_confirmed = models.BooleanField(default=True)

    def __str__(self):
        return self.name

def generate_letter_id():
    letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    # Generate combinations of letters and numbers
    combinations = [f'{letter}{num}' for letter in letters for num in range(1, 1000)]
    for combination in combinations:
        yield combination

class order(models.Model):
    MALE = 'M'
    FEMALE = 'F'

    TYPE1 = 't1'
    # change this to all types from front-end

    UNDERWAY = 'u'
    END = 'e'
    # change this to all status from front-end

    GENDER_CHOICES = [
        (MALE, 'Male'),
        (FEMALE, 'Female'),
    ]

    TYPE_CHOICES = [
        (TYPE1, 'Type 1')
        # change this to all types from front-end
    ]

    STATUS_CHOICES = [
        (UNDERWAY, 'Underway'),
        (END, 'End')
    ]

    letter_id = models.CharField(max_length=10, unique=True, null=True, blank=True)
    doctor = models.ForeignKey(
        DoctorProfile, on_delete=models.CASCADE, related_name='orders', null=True, blank=True)
    name = models.CharField(max_length=255)
    age = models.IntegerField()
    teethNbr = models.IntegerField()
    gender = models.CharField(
        max_length=1, choices=GENDER_CHOICES, default=MALE)
    color = models.CharField(max_length=7, null=True, blank=True)
    type = models.CharField(
        max_length=2, choices=TYPE_CHOICES, null=True, blank=True)
    status = models.CharField(
        max_length=1, choices=STATUS_CHOICES, default=UNDERWAY)
    last_updated = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True, null=True, blank=True)
    note = models.TextField(null=True, blank=True)
    price = models.DecimalField(
        max_digits=7, decimal_places=2, default=0)
    been_payed = models.DecimalField(
        max_digits=7, decimal_places=2, default=0)
    not_payed = models.DecimalField(
        max_digits=7, decimal_places=2, default=0)
    from_laboratory = models.BooleanField(default=False)
    is_delivered = models.BooleanField(default=False)
    is_deleted_from_doctor = models.BooleanField(default=False)
    is_deleted_from_laboratory = models.BooleanField(default=False)

    def save(self, *args, **kwargs):
        if not self.letter_id:
            for new_letter_id in generate_letter_id():
                if not order.objects.filter(letter_id=new_letter_id).exists():
                    self.letter_id = new_letter_id
                    break
        super().save(*args, **kwargs)

    def __str__(self):
        return str(self.letter_id) + "- " + self.name
    
    class Meta:
        ordering = ['-created_at']


class OrderRecords(models.Model):
    order = models.ForeignKey(
        order, on_delete=models.CASCADE, related_name='records', null=True, blank=True)
    voice_record = models.FileField(
        upload_to='voice_records/', null=True, blank=True)
    voice_text = models.TextField(null=True, blank=True)

    class Meta:
        ordering = ['pk']


class Contract(models.Model):
    doctor = models.ForeignKey(
        DoctorProfile, on_delete=models.CASCADE, related_name='doctorcontracts')
    lab = models.ForeignKey(
        LaboratoryProfile, on_delete=models.CASCADE, related_name='lab_contracts')
    description = models.CharField(max_length=256, null=True, blank=True)
    zircon_wave = models.DecimalField(
        max_digits=7, decimal_places=2, default=0)
    zircon_dental_direct = models.DecimalField(
        max_digits=7, decimal_places=2, default=0)
    zircon_emax_prime_ivoclar = models.DecimalField(
        max_digits=7, decimal_places=2, default=0)
    impress_crown = models.DecimalField(
        max_digits=7, decimal_places=2, default=0)
    impress_intaly = models.DecimalField(
        max_digits=7, decimal_places=2, default=0)
    impress_onlay = models.DecimalField(
        max_digits=7, decimal_places=2, default=0)
    impress_overlay = models.DecimalField(
        max_digits=7, decimal_places=2, default=0)
    pfm = models.DecimalField(max_digits=7, decimal_places=2, default=0)
    implant_zircon = models.DecimalField(
        max_digits=7, decimal_places=2, default=0)
    implant_pfm = models.DecimalField(
        max_digits=7, decimal_places=2, default=0)
    night_gard = models.DecimalField(max_digits=7, decimal_places=2, default=0)
    night_white = models.DecimalField(
        max_digits=7, decimal_places=2, default=0)
    retainer = models.DecimalField(max_digits=7, decimal_places=2, default=0)
    study_model = models.DecimalField(
        max_digits=7, decimal_places=2, default=0)
    snap_on_smile = models.DecimalField(
        max_digits=7, decimal_places=2, default=0)

    class Meta:
        unique_together = ('doctor', 'lab',)

    def __str__(self):
        return str(self.pk) + "- " + str(self.doctor) + " - " + str(self.lab) + "- " + str(self.description)
