from datetime import datetime, timedelta
import json
from pathlib import Path
from django.conf import settings
from django.forms import ValidationError
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.generics import ListAPIView, RetrieveAPIView, CreateAPIView, RetrieveUpdateAPIView, UpdateAPIView, ListCreateAPIView
from rest_framework.authentication import SessionAuthentication, BasicAuthentication
from rest_framework import status
from .models import order, Contract
from .serializers import *
from .permissions import *
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password
from django.contrib.auth import login, authenticate
from django.http import JsonResponse
from django.db import models
from django.db.models import Sum, Count, F, Value
from django.middleware.csrf import get_token
from django.views.decorators.csrf import csrf_exempt
from rest_framework_simplejwt.tokens import RefreshToken
import speech_recognition as sr
from pydub import AudioSegment
from django.utils import timezone


def isDoctor(user):
    return user.userprofile.role == 'd' if hasattr(user, 'userprofile') else False


def isConfirmedDoctor(user):
    if hasattr(user, 'userprofile'):
        if hasattr(user, 'doctorprofile'):
            return user.doctorprofile.is_confirmed
    return False


def isLaboratory(user):
    return user.userprofile.role == 'l' if hasattr(user, 'userprofile') else False


def isDelivery(user):
    return user.userprofile.role == 'e' if hasattr(user, 'userprofile') else False


def audio_to_text(blob):
    recognizer = sr.Recognizer()

    # Recognize the audio
    with sr.AudioFile(blob) as source:
        audio_data = recognizer.record(source)

    # Recognize speech using Google Speech Recognition
    try:
        text = recognizer.recognize_google(audio_data)
        return text
    except sr.UnknownValueError:
        return "Google Speech Recognition could not understand audio"
    except sr.RequestError as e:
        return "Could not request results from Google Speech Recognition service; {0}".format(e)


def turn_to_speech(order_instance):
    serializer = AllOrdersSerializer(order_instance)
    try:
        blob_data = serializer.data.get('records')[-1].get('voice_record')
        base_dir = settings.BASE_DIR
        voice_file_path = f'{base_dir}{blob_data}'

        full_path = Path(voice_file_path)

        if full_path.is_absolute():
            try:
                sound = AudioSegment.from_ogg(voice_file_path)
                sound.export(voice_file_path, format="wav")
            except Exception as e:
                print(f'----exception---- {e}')
            text = audio_to_text(voice_file_path)
        else:
            text = audio_to_text(str(full_path.absolute()))

        # Assuming one-to-many relationship
        record_instance = order_instance.records.last()
        record_instance.voice_text = text
        record_instance.save()
        # Add the text to the field voice_text  in records of this order instance
        records = serializer.data.get('records')[-1]
        records['voice_text'] = text
        order_instance.note = serializer.data['note'] + " ; " + text
        order_instance.save()
        serializer.data['records'] = records

    except Exception as e:
        print('cant convert file into speech', str(e))


# for doctors only
class OrderDetailViewDoc(ListAPIView):
    serializer_class = AllOrdersSerializer
    permission_classes = [IsSubscribed,
                          IsAuthenticated, IsDoctor, IsConfirmedDoctor]

    def get_queryset(self):
        queryset = order.objects.filter(
            doctor=self.request.user.doctorprofile,
            is_deleted_from_doctor=False)

        # Check if a filter parameter is provided in the URL
        status_filter = self.request.query_params.get('status', None)
        if status_filter is not None:
            queryset = queryset.filter(
                status=status_filter)

        queryset = queryset.annotate(doctor_name=F('doctor__name'))

        return queryset


# for laboratories only
class OrderDetailViewLab(ListAPIView):
    serializer_class = AllOrdersSerializer
    permission_classes = [IsSubscribed, IsAuthenticated, IsLaboratory]

    def get_queryset(self):
        queryset = order.objects.filter(
            doctor__laboratory=self.request.user.laboratoryprofile,
            is_deleted_from_laboratory=False)

        # Check if a filter parameter is provided in the URL
        status_filter = self.request.query_params.get('status', None)
        if status_filter is not None:
            queryset = queryset.filter(
                status=status_filter)

        queryset = queryset.annotate(doctor_name=F('doctor__name'))

        return queryset


# for deliveries only
class OrderDetailViewDel(ListAPIView):
    serializer_class = AllOrdersSerializer
    permission_classes = [IsAuthenticated, IsDelivery]

    def get_queryset(self):
        queryset = order.objects.filter(is_delivered=False)

        # Check if a filter parameter is provided in the URL
        status_filter = self.request.query_params.get('status', None)
        if status_filter is not None:
            queryset = queryset.filter(
                status=status_filter)

        # Filter orders based on subscription_expiry of laboratoryprofile
        now = timezone.now()
        queryset = queryset.filter(
            doctor__laboratory__isnull=False,
            doctor__laboratory__issubscribed=True
        )

        queryset = queryset.annotate(doctor_name=F('doctor__name'))

        return queryset


# for doctors only
class OrderRetreiveViewDoc(APIView):
    permission_classes = [IsSubscribed,
                          IsAuthenticated, IsDoctor, IsConfirmedDoctor]

    def get(self, request, order_id):
        try:
            order_instance = order.objects.get(
                id=order_id, doctor=request.user.doctorprofile)
        except order_instance.DoesNotExist:
            return Response({"error": "Order not found"}, status=status.HTTP_404_NOT_FOUND)

        serializer = AllOrdersSerializer(order_instance)
        return Response(serializer.data)


# for laboratories only
class OrderRetreiveViewLab(APIView):
    permission_classes = [IsSubscribed, IsAuthenticated, IsLaboratory]

    def get(self, request, order_id):
        try:
            order_instance = order.objects.get(id=order_id)
        except order_instance.DoesNotExist:
            return Response({"error": "Order not found"}, status=status.HTTP_404_NOT_FOUND)

        serializer = AllOrdersSerializer(order_instance)
        return Response(serializer.data)


# for delivery only
class OrderRetreiveViewDel(APIView):
    permission_classes = [IsAuthenticated, IsDelivery]

    def get(self, request, order_id):
        try:
            order_instance = order.objects.get(id=order_id)
        except order_instance.DoesNotExist:
            return Response({"error": "Order not found"}, status=status.HTTP_404_NOT_FOUND)

        serializer = AllOrdersSerializer(order_instance)
        return Response(serializer.data)


# for doctors only
class CreateOrderDetailView(CreateAPIView):
    queryset = order.objects.all()
    serializer_class = CreateOrderSerializer
    permission_classes = [IsSubscribed,
                          IsAuthenticated, IsDoctor, IsConfirmedDoctor]

    def perform_create(self, serializer):
        # Get the logged-in doctor
        doctor = self.request.user.doctorprofile
        records = None
        if 'voice_record' in self.request.FILES:
            records = self.request.FILES['voice_record']

        # Assign the doctor to the order being created
        serializer.save(doctor=doctor, records=records)
        order_instance = order.objects.get(
            id=serializer.data['id'], doctor=doctor)
        if records is not None:
            # convert speech to text and save it into db
            turn_to_speech(order_instance)
        else:
            print(records)
            print(self.request.FILES)


# for all users (deferent action for each role)
class OrderDeleteView(RetrieveUpdateAPIView):
    permission_classes = [IsSubscribed, IsAuthenticated]
    serializer_class = AllOrdersSerializer

    def get_object(self):
        if not self.kwargs['pk']:
            return Response({'message': 'Missing order id.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            order_instance = order.objects.get(pk=self.kwargs['pk'])
        except order.DoesNotExist:
            return Response({'message': 'Order not found.'}, status=status.HTTP_404_NOT_FOUND)

        return order_instance

    def perform_update(self, serializer):
        if isLaboratory(self.request.user):
            serializer.save(is_deleted_from_laboratory=True)
        if isDoctor(self.request.user):
            serializer.save(is_deleted_from_doctor=True)
        if isDelivery(self.request.user):
            serializer.save(is_delivered=True)


# for doctors only
class OrderUpdateViewDoc(UpdateAPIView):
    queryset = order.objects.all()
    serializer_class = CreateOrderSerializer
    permission_classes = [IsSubscribed,
                          IsAuthenticated, IsDoctor, IsConfirmedDoctor]
    lookup_field = 'pk'  # Explicitly define the lookup field

    def perform_update(self, serializer):
        # Get the logged-in doctor
        doctor = self.request.user.doctorprofile
        records = None
        if 'voice_record' in self.request.FILES:
            records = self.request.FILES['voice_record']

        # Assign the doctor to the order being created
        if records is not None:
            serializer.save(doctor=doctor, records=records)
            order_instance = order.objects.get(
                id=serializer.data['id'], doctor=doctor)
            # convert speech to text and save it into db
            turn_to_speech(order_instance)
        else:
            serializer.save()


# for laboratories only
class OrderUpdateViewLab(UpdateAPIView):
    queryset = order.objects.all()
    serializer_class = CreateOrderSerializer
    permission_classes = [IsSubscribed, IsAuthenticated, IsLaboratory]
    lookup_field = 'pk'  # Explicitly define the lookup field


# for delivery only
class OrderUpdateViewDel(UpdateAPIView):
    queryset = order.objects.all()
    serializer_class = CreateOrderSerializer
    permission_classes = [IsAuthenticated, IsDelivery]
    lookup_field = 'pk'  # Explicitly define the lookup field


# for doctor only
class UploadVoiceRecord(CreateAPIView):
    queryset = OrderRecords.objects.all()
    serializer_class = OrderRecordsSerializer
    permission_classes = [IsSubscribed,
                          IsAuthenticated, IsDoctor, IsConfirmedDoctor]

    def perform_create(self, serializer):
        # Get the logged-in doctor
        doctor = self.request.user.doctorprofile

        # Assign the doctor to the order being created
        serializer.save(doctor=doctor)


# depricated (for delivery only)
class MarkAsDeliveredView(UpdateAPIView):
    """Mark an order as delivered by a delivery person."""
    permission_classes = [IsAuthenticated, IsDelivery]
    serializer_class = CreateOrderSerializer

    def get_object(self):
        if order.objects.filter(pk=self.request.data.get('pk', {})).exists():
            order_instance = order.objects.get(
                pk=self.request.data.get('pk', {}))
            return order_instance

    def perform_update(self, serializer):
        serializer.save(is_delivered=True)


# authentication not required
class CreateUserDetailView(APIView):
    def post(self, request, *args, **kwargs):
        # Extract UserProfile data from request.data
        user_data = request.data.get('user', {})
        if 'password' in user_data:  # Check if password is provided
            user_data['is_active'] = True
            user_data['password'] = make_password(
                user_data['password'])  # Hash the password
        user_serializer = CreateUserSerializer(data=user_data)

        if user_serializer.is_valid():
            user = user_serializer.save()

            # Extract UserProfile data from request.data
            user_profile_data = request.data.get('user_profile', {})
            # Link the UserProfile to the created user
            user_profile_data['user'] = user.id

            user_profile_serializer = UserProfileSerializer(
                data=user_profile_data)

            if user_profile_serializer.is_valid():
                userprofile = user_profile_serializer.save()
                # if user role is doctor create doctor profile (instance name is specific_profile)
                specific_profile_serializer = False
                if str(user_profile_data["role"]) == "d":
                    # get doctor data
                    specific_profile_data = request.data.get(
                        'doctor_profile', {})
                    specific_profile_data['user'] = user.id
                    specific_profile_serializer = DoctorProfileSerializer(
                        data=specific_profile_data)
                # if user role is laboratory create laboratory profile (instance name is specific_profile)
                if str(user_profile_data["role"]) == "l":
                    # get laboratory data
                    specific_profile_data = request.data.get(
                        'laboratory_profile', {})
                    specific_profile_data['user'] = user.id
                    specific_profile_serializer = LaboratoryProfileSerializer(
                        data=specific_profile_data)
                # if isvalid() return response
                if str(user_profile_data["role"]) == "d" or str(user_profile_data["role"]) == "l":
                    if specific_profile_serializer.is_valid():
                        specific_profile_serializer.save()
                    else:
                        user.delete()
                        userprofile.delete()
                        return Response(specific_profile_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

                signin_response = SigninAPIView().post(request, format=None, user=user)
                return Response(
                    {'user': user_serializer.data,
                        'user_profile': user_profile_serializer.data,
                        'specific_profile': specific_profile_serializer.data if specific_profile_serializer else "normal user",
                        'login_info': str(signin_response), },
                    status=status.HTTP_201_CREATED
                )
            else:
                # If UserProfile data is not valid, delete the created user
                user.delete()
                return Response(user_profile_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response(user_serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# this is not used (can't use basic auth in this project)
class SigninAPIView(APIView):
    authentication_classes = [SessionAuthentication, BasicAuthentication]

    def post(self, request, format=None, user=None):
        username = request.data.get('username')
        password = request.data.get('password')

        if user is None:
            user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            content = {
                'message': 'Login successful',
                'user': str(user),
            }
            return JsonResponse(content)
        else:
            content = {'error': "Invalid user", }
            return Response(content, status=401)


# authentication not required
@csrf_exempt
def Signin(request, user=None):
    username = None
    password = None
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        data = {}
    if request.method == 'POST':
        username = data.get('username')
        password = data.get('password')
    if user is None:
        if username and password:
            user = authenticate(request, username=username, password=password)

    if user is not None:
        login(request, user)
        # Generate access token
        refresh = RefreshToken.for_user(user)
        token = str(refresh.access_token)
        content = {
            'message': 'Login successful',
            'user': str(user),
            'id': user.pk,
            'token': token,
        }
        return JsonResponse(content, status=status.HTTP_200_OK)
    else:
        content = {'error': "Invalid user",
                   'status': status.HTTP_401_UNAUTHORIZED,
                   'username': str(request.POST), }
        return JsonResponse(content, status=status.HTTP_401_UNAUTHORIZED)


# for testing purpose only
class ProfileAPIView(APIView):
    # authentication_classes = [SessionAuthentication, BasicAuthentication]
    permission_classes = [IsSubscribed, IsAuthenticated]

    def get(self, request, format=None):
        content = {
            'message': 'This is a protected view',
            'user': str(request.user),
        }
        return Response(content)


# for laboratories only
# list all orders for the current logged-in laboratory
class FinancialsDetailView(ListAPIView):
    serializer_class = FinancialsSerializer
    permission_classes = [IsSubscribed, IsAuthenticated, IsLaboratory]

    def get_queryset(self):
        start_date = self.request.query_params.get('start_date')
        end_date = self.request.query_params.get('end_date')
        queryset = []
        if start_date and end_date:
            try:
                start_date = datetime.strptime(start_date, '%Y-%m-%d')
                end_date = datetime.strptime(
                    end_date, '%Y-%m-%d') + timedelta(days=1)
                queryset = order.objects.filter(
                    doctor__laboratory=self.request.user.laboratoryprofile,
                    last_updated__range=[start_date, end_date]
                ).values('doctor__name', 'doctor').annotate(total_price=Sum('price'),  total_been_payed=Sum('been_payed'),  total_not_payed=Sum('not_payed'),  total_orders=Count('price'))
            except ValueError:
                queryset = []
        else:
            queryset = order.objects.filter(
                doctor__laboratory=self.request.user.laboratoryprofile
            ).values('doctor__name', 'doctor').annotate(total_price=Sum('price'),  total_been_payed=Sum('been_payed'),  total_not_payed=Sum('not_payed'),  total_orders=Count('price'))
        return queryset


# for delivery only
class DeliveryFinancialsDetailView(ListAPIView):
    serializer_class = DeliveryFinancialsSerializer
    permission_classes = [IsAuthenticated, IsDelivery]

    def get_queryset(self):
        start_date = self.request.data.get('start_date', None)
        end_date = self.request.data.get('end_date', None)
        queryset = []
        price = 0
        been_payed = 0
        not_payed = 0
        if start_date and end_date:
            try:
                start_date = datetime.strptime(start_date, '%Y-%m-%d')
                end_date = datetime.strptime(
                    end_date, '%Y-%m-%d') + timedelta(days=1)
                queryset = order.objects.filter(
                    is_delivered=True,
                    last_updated__range=[start_date, end_date]
                )
                for order_obj in queryset:
                    if order_obj.from_laboratory:
                        order_obj.price = order_obj.price * 2
                queryset = queryset.values('doctor__laboratory__name').annotate(total_price=Sum('price'),  total_been_payed=Sum(
                    'been_payed'),  total_not_payed=Sum('not_payed'),  total_orders=Count('price'))
            except ValueError:
                queryset = []
        else:
            queryset = order.objects.filter(
                is_delivered=True,
            )
            for order_obj in queryset:
                if order_obj.from_laboratory:
                    price = price + order_obj.price * 2
                    been_payed = been_payed + order_obj.been_payed * 2
                    not_payed = not_payed + order_obj.not_payed * 2
                else:
                    price = price + order_obj.price
                    been_payed = been_payed + order_obj.been_payed
                    not_payed = not_payed + order_obj.not_payed
            queryset = queryset.values('doctor__laboratory__name').annotate(total_price=Value(price, output_field=models.DecimalField()),  total_been_payed=Value(
                been_payed, output_field=models.DecimalField()),  total_not_payed=Value(not_payed, output_field=models.DecimalField()),  total_orders=Count('price'))
        return queryset


# for laboratories only
# contracts
class ContractRetrieveOrCreateView(RetrieveAPIView):
    serializer_class = ContractSerializer
    permission_classes = [IsSubscribed, IsAuthenticated, IsLaboratory]

    def get_object(self):
        if not self.kwargs['pk']:
            return Response({'message': 'Missing order id.'}, status=status.HTTP_400_BAD_REQUEST)
        doctor_pk = self.kwargs['pk']
        if DoctorProfile.objects.filter(pk=doctor_pk).exists():
            doctor = DoctorProfile.objects.get(pk=doctor_pk)
            user = self.request.user
            # Retrieve existing contract if it exists
            if doctor.laboratory is None:
                doctor.laboratory = user.laboratoryprofile
                doctor.save()
            if doctor.laboratory == user.laboratoryprofile:
                try:
                    contract_instance = Contract.objects.get(
                        doctor=doctor, lab=user.laboratoryprofile)
                    return contract_instance
                except Contract.DoesNotExist:
                    # Create a new contract if it doesn't exist
                    new_contract = Contract.objects.create(
                        doctor=doctor, lab=user.laboratoryprofile)
                    new_contract.save()
                    return new_contract
            raise ValidationError("doctor is assigned to other lab")

        raise ValidationError("Invalid doctor")

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return Response(serializer.data)


# for laboratories only
class ContractUpdateView(UpdateAPIView):
    queryset = Contract.objects.all()
    serializer_class = ContractSerializer
    permission_classes = [IsSubscribed, IsAuthenticated, IsLaboratory]
    lookup_field = 'pk'  # Explicitly define the lookup field

# authentication not required


def get_csrf_token(request):
    csrf_token = get_token(request)
    return JsonResponse({'csrfToken': csrf_token})


# for laboratory only
# get doctors of current laboratory logged in
class LabDoctorsDetailView(APIView):
    permission_classes = [IsSubscribed, IsAuthenticated, IsLaboratory]

    def get(self, request):
        laboratory = self.request.user.laboratoryprofile
        doctors_list = DoctorProfile.objects.filter(laboratory=laboratory)
        doctors_serializer = DoctorProfileForLaboratorySerializer(
            doctors_list, many=True, context={'request': request})
        return Response(doctors_serializer.data)


# for laboratory only
# make a doctor's laboratory current laboratory
class SetLabToDoctorView(UpdateAPIView):
    """
    A view to set a doctor's laboratory.
    """
    permission_classes = [IsSubscribed, IsAuthenticated, IsLaboratory]
    serializer_class = DoctorProfileSerializer

    def get_object(self):
        doctor = None
        if User.objects.filter(pk=self.request.data.get('pk', {})).exists():
            doctor = User.objects.get(pk=self.request.data['pk'])
        if DoctorProfile.objects.filter(user=doctor).exists():
            doctor_profile_instance = DoctorProfile.objects.get(
                user=doctor)
            return doctor_profile_instance
        return None

    def perform_update(self, serializer):
        obj = self.get_object()
        if not obj:
            raise ValidationError("Invalid data")
        else:
            laboratory = self.request.user.laboratoryprofile
            serializer.save(laboratory=laboratory)

# for laboratory only
# make a doctor's laboratory null


class RemoveLabFromDoctorView(UpdateAPIView):
    """
    A view to set a doctor's laboratory.
    """
    permission_classes = [IsSubscribed, IsAuthenticated, IsLaboratory]
    serializer_class = DoctorProfileSerializer

    def get_object(self):
        if DoctorProfile.objects.filter(pk=self.request.data.get('pk', {})).exists():
            doctor_profile_instance = DoctorProfile.objects.get(
                pk=self.request.data.get('pk', {}))
            return doctor_profile_instance

    def perform_update(self, serializer):
        laboratory = self.request.user.laboratoryprofile
        if serializer.instance.laboratory == laboratory:
            if serializer.is_valid():
                serializer.save(laboratory=None)


# for delivery only
class CheckLabSubscription(RetrieveAPIView):
    queryset = LaboratoryProfile.objects.all()
    serializer_class = LabSubscriptionSerializer
    permission_classes = [IsAuthenticated, IsDelivery]


# for delivery only
class ChangeLabAddress(APIView):
    permission_classes = [IsAuthenticated, IsDelivery]

    def post(self, request, *args, **kwargs):
        lab_id = kwargs['lab_id']
        if 'address' in request.data and request.data['address'] != "":
            try:
                lab = LaboratoryProfile.objects.get(pk=lab_id)
                userprofile = lab.user.userprofile
                userprofile.address = request.data['address']
                userprofile.save()
                return Response({"message": "Successfully changed address."}, status=status.HTTP_200_OK)
            except LaboratoryProfile.DoesNotExist:
                return Response({"error": "The specified laboratory does not exist."}, status=status.HTTP_404_NOT_FOUND)
            except:
                raise ValidationError('Unknown Problem')
        return Response({"error": "No valid data provided"}, status=status.HTTP_400_BAD_REQUEST)


# for delivery only
class ChangeDocAddress(APIView):
    permission_classes = [IsAuthenticated, IsDelivery]

    def post(self, request, *args, **kwargs):
        lab_id = kwargs['lab_id']
        if 'address' in request.data and request.data['address'] != "":
            try:
                lab = DoctorProfile.objects.get(pk=lab_id)
                userprofile = lab.user.userprofile
                userprofile.address = request.data['address']
                userprofile.save()
                return Response({"message": "Successfully changed address."}, status=status.HTTP_200_OK)
            except DoctorProfile.DoesNotExist:
                return Response({"error": "The specified doctor does not exist."}, status=status.HTTP_404_NOT_FOUND)
            except:
                raise ValidationError('Unknown Problem')
        return Response({"error": "No valid data provided"}, status=status.HTTP_400_BAD_REQUEST)


# for laboratory only
# toogle the subscription in delivery service by setting  is_subscribed field of UserProfile model
class ToggleSubscription(UpdateAPIView):
    permission_classes = [IsAuthenticated, IsLaboratory]
    serializer_class = LaboratoryProfileSerializer

    def get_object(self):
        return self.request.user.laboratoryprofile

    def perform_update(self, serializer):
        instance = self.get_object()
        if instance.issubscribed:
            instance.issubscribed = False
        else:
            instance.issubscribed = True
        instance.save()
        return instance


# for laboratory only
class ReturnToDoc(UpdateAPIView):
    permission_classes = [IsAuthenticated, IsLaboratory]
    serializer_class = SimpleOrderSerializer

    def get_object(self):
        if not self.kwargs['pk']:
            return Response({'message': 'Missing order id.'}, status=status.HTTP_400_BAD_REQUEST)
        order_pk = self.kwargs['pk']
        try:
            order_instance = order.objects.get(id=order_pk)
            if order_instance.from_laboratory:
                order_instance.from_laboratory = False
            else:
                order_instance.from_laboratory = True
                order_instance.is_delivered = False
            order_instance.status = order.UNDERWAY
            order_instance.save()
            return Response({'message': 'Order is completed from laboratory and it will back to doctor'})
        except order.DoesNotExist:
            return Response({'message': 'The requested order does not exist'}, status=status.HTTP_404_NOT_FOUND)


# for laboratory only
class GetLaboratoryProfile(RetrieveAPIView):
    serializer_class = LaboratoryProfileSerializer
    permission_classes = [IsAuthenticated, IsLaboratory]

    def get_object(self):
        # Get the profile associated with the authenticated user
        return self.request.user.laboratoryprofile

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return Response(serializer.data)
