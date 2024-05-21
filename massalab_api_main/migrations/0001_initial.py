# Generated by Django 5.0.4 on 2024-04-08 22:30

import django.db.models.deletion
import phonenumber_field.modelfields
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='LaboratoryProfile',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=255)),
                ('issubscribed', models.BooleanField(default=False)),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='DoctorProfile',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=255, null=True)),
                ('is_confirmed', models.BooleanField(default=True)),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
                ('laboratory', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='doctors', to='massalab_api_main.laboratoryprofile')),
            ],
        ),
        migrations.CreateModel(
            name='order',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('letter_id', models.CharField(blank=True, max_length=10, null=True, unique=True)),
                ('name', models.CharField(max_length=255)),
                ('age', models.IntegerField()),
                ('teethNbr', models.IntegerField()),
                ('gender', models.CharField(choices=[('M', 'Male'), ('F', 'Female')], default='M', max_length=1)),
                ('color', models.CharField(blank=True, max_length=7, null=True)),
                ('type', models.CharField(blank=True, choices=[('t1', 'Type 1')], max_length=2, null=True)),
                ('status', models.CharField(choices=[('u', 'Underway'), ('e', 'End')], default='u', max_length=1)),
                ('last_updated', models.DateTimeField(auto_now=True)),
                ('created_at', models.DateTimeField(auto_now_add=True, null=True)),
                ('note', models.TextField(blank=True, null=True)),
                ('price', models.DecimalField(decimal_places=2, default=0, max_digits=7)),
                ('been_payed', models.DecimalField(decimal_places=2, default=0, max_digits=7)),
                ('not_payed', models.DecimalField(decimal_places=2, default=0, max_digits=7)),
                ('from_laboratory', models.BooleanField(default=False)),
                ('is_delivered', models.BooleanField(default=False)),
                ('is_deleted_from_doctor', models.BooleanField(default=False)),
                ('is_deleted_from_laboratory', models.BooleanField(default=False)),
                ('doctor', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='orders', to='massalab_api_main.doctorprofile')),
            ],
            options={
                'ordering': ['-created_at'],
            },
        ),
        migrations.CreateModel(
            name='OrderRecords',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('voice_record', models.FileField(blank=True, null=True, upload_to='voice_records/')),
                ('voice_text', models.TextField(blank=True, null=True)),
                ('order', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='records', to='massalab_api_main.order')),
            ],
            options={
                'ordering': ['pk'],
            },
        ),
        migrations.CreateModel(
            name='UserProfile',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('role', models.CharField(choices=[('d', 'Doctor'), ('l', 'Laboratory'), ('e', 'Delivery'), ('n', 'Normal')], default='n', max_length=1)),
                ('phoneNumber', phonenumber_field.modelfields.PhoneNumberField(blank=True, max_length=128, null=True, region=None, unique=True)),
                ('address', models.CharField(blank=True, null=True)),
                ('building_nbr', models.CharField(blank=True, null=True)),
                ('floor_nbr', models.CharField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True, null=True)),
                ('subscription_expiry', models.DateTimeField(blank=True, null=True)),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='Contract',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('description', models.CharField(blank=True, max_length=256, null=True)),
                ('zircon_wave', models.DecimalField(decimal_places=2, default=0, max_digits=7)),
                ('zircon_dental_direct', models.DecimalField(decimal_places=2, default=0, max_digits=7)),
                ('zircon_emax_prime_ivoclar', models.DecimalField(decimal_places=2, default=0, max_digits=7)),
                ('impress_crown', models.DecimalField(decimal_places=2, default=0, max_digits=7)),
                ('impress_intaly', models.DecimalField(decimal_places=2, default=0, max_digits=7)),
                ('impress_onlay', models.DecimalField(decimal_places=2, default=0, max_digits=7)),
                ('impress_overlay', models.DecimalField(decimal_places=2, default=0, max_digits=7)),
                ('pfm', models.DecimalField(decimal_places=2, default=0, max_digits=7)),
                ('implant_zircon', models.DecimalField(decimal_places=2, default=0, max_digits=7)),
                ('implant_pfm', models.DecimalField(decimal_places=2, default=0, max_digits=7)),
                ('night_gard', models.DecimalField(decimal_places=2, default=0, max_digits=7)),
                ('night_white', models.DecimalField(decimal_places=2, default=0, max_digits=7)),
                ('retainer', models.DecimalField(decimal_places=2, default=0, max_digits=7)),
                ('study_model', models.DecimalField(decimal_places=2, default=0, max_digits=7)),
                ('snap_on_smile', models.DecimalField(decimal_places=2, default=0, max_digits=7)),
                ('doctor', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='doctorcontracts', to='massalab_api_main.doctorprofile')),
                ('lab', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='lab_contracts', to='massalab_api_main.laboratoryprofile')),
            ],
            options={
                'unique_together': {('doctor', 'lab')},
            },
        ),
    ]