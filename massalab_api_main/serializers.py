from rest_framework import serializers
from .models import order, OrderRecords, UserProfile, DoctorProfile, LaboratoryProfile, Contract
from django.contrib.auth.models import User


class GetUserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = '__all__'


class GetUserSerializer(serializers.ModelSerializer):
    userprofile = GetUserProfileSerializer()

    class Meta:
        model = User
        fields = '__all__'


class SimpleOrderSerializer(serializers.ModelSerializer):
    class Meta:
        model = order
        fields = '__all__'


class LaboratoryProfileSerializer(serializers.ModelSerializer):
    user = GetUserSerializer()

    class Meta:
        model = LaboratoryProfile
        fields = '__all__'


class DoctorProfileForDeliverySerializer(serializers.ModelSerializer):
    laboratory = LaboratoryProfileSerializer()
    user = GetUserSerializer()

    class Meta:
        model = DoctorProfile
        fields = '__all__'


class OrderRecordsSerializer(serializers.ModelSerializer):
    class Meta:
        model = OrderRecords
        fields = '__all__'


class AllOrdersSerializer(serializers.ModelSerializer):
    records = OrderRecordsSerializer(many=True, required=False)
    doctor_name = serializers.CharField(source='doctor.name', read_only=True)
    voicetext = serializers.CharField(required=False)
    doctor = DoctorProfileForDeliverySerializer()

    class Meta:
        model = order
        fields = '__all__'


class FinancialsSerializer(serializers.Serializer):
    doctor = serializers.IntegerField()
    doctor__name = serializers.CharField()
    total_orders = serializers.IntegerField()
    total_price = serializers.DecimalField(max_digits=10, decimal_places=2)
    total_been_payed = serializers.DecimalField(
        max_digits=10, decimal_places=2)
    total_not_payed = serializers.DecimalField(max_digits=10, decimal_places=2)

    class Meta:
        fields = '__all__'


class DeliveryFinancialsSerializer(serializers.Serializer):
    doctor__laboratory__name = serializers.CharField()
    total_orders = serializers.IntegerField()
    total_price = serializers.DecimalField(max_digits=10, decimal_places=2)
    total_been_payed = serializers.DecimalField(
        max_digits=10, decimal_places=2)
    total_not_payed = serializers.DecimalField(max_digits=10, decimal_places=2)

    class Meta:
        fields = '__all__'


class CreateOrderSerializer(serializers.ModelSerializer):
    records = OrderRecordsSerializer(many=True, required=False)

    class Meta:
        model = order
        # fields = ['name', 'age', 'teethNbr', 'gender', 'color',
        #           'type', 'status', 'note', 'price', 'is_delivered', 'records']
        fields = '__all__'

    def create(self, validated_data):
        records_data = validated_data.pop('records', None)
        order_instance = order.objects.create(**validated_data)
        if records_data:
            records_instance = OrderRecords.objects.create(
                order=order_instance, voice_record=records_data)
        order_instance.save()
        return order_instance

    def update(self, instance, validated_data):
        records_data = validated_data.pop('records', None)
        for field in validated_data:
            setattr(instance, field, validated_data[field])
        # instance.name = validated_data.get('name', instance.name)
        # instance.age = validated_data.get('age', instance.age)
        # instance.teethNbr = validated_data.get('teethNbr', instance.teethNbr)
        # instance.gender = validated_data.get('gender', instance.gender)
        # instance.color = validated_data.get('color', instance.color)
        # instance.type = validated_data.get('type', instance.type)
        # instance.status = validated_data.get('status', instance.status)
        # instance.note = validated_data.get('note', instance.note)
        # instance.price = validated_data.get('price', instance.price)
        # instance.is_delivered = validated_data.get('is_delivered', instance.is_delivered)
        order_instance = instance
        if records_data:
            records_instance = OrderRecords.objects.create(
                order=order_instance, voice_record=records_data)
        order_instance.save()
        return order_instance


class CreateUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'


class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = '__all__'


class DoctorProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = DoctorProfile
        fields = '__all__'


class ContractSerializer(serializers.ModelSerializer):
    doctor = DoctorProfileSerializer(read_only=True)

    class Meta:
        model = Contract
        fields = '__all__'


class DoctorProfileForLaboratorySerializer(serializers.ModelSerializer):
    doctorcontracts = serializers.SerializerMethodField()

    class Meta:
        model = DoctorProfile
        fields = '__all__'

    def get_doctorcontracts(self, obj):
        # Get the request object from the serializer context
        request = self.context.get('request')
        # doctor = self.get_object()
        # doctorcontracts = doctor.doctorcontracts.all()

        # # Filter by lab and description
        # contract_descriptions = Contract.objects.filter(lab=doctor.laboratoryprofile)
        if Contract.objects.filter(
                doctor=obj, lab=request.user.laboratoryprofile).exists():
            doctorcontracts = Contract.objects.get(
                doctor=obj, lab=request.user.laboratoryprofile)

            # filtered_contracts = ContractSerializer(doctorcontracts)

            return ContractSerializer(doctorcontracts).data


class LabSubscriptionSerializer(serializers.ModelSerializer):
    class Meta:
        model = LaboratoryProfile
        fields = ['is_subscribed']
