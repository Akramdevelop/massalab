from rest_framework.permissions import BasePermission
from django.utils import timezone


class IsDoctor(BasePermission):
    """
    Custom permission to only allow users with the role "doctor".
    """

    message = "You are not a doctor"

    def has_permission(self, request, view):
        # Check if the user's role is "doctor"
        return request.user.userprofile.role == 'd' if hasattr(request.user, 'userprofile') else False


class IsLaboratory(BasePermission):
    """
    Custom permission to only allow users with the role "laboratory".
    """

    message = "You are not a laboratory"

    def has_permission(self, request, view):
        # Check if the user's role is "doctor"
        return request.user.userprofile.role == 'l' if hasattr(request.user, 'userprofile') else False


class IsDelivery(BasePermission):
    """
    Custom permission to only allow users with the role "laboratory".
    """

    message = "You are not a delivery"

    def has_permission(self, request, view):
        # Check if the user's role is "doctor"
        return request.user.userprofile.role == 'e' if hasattr(request.user, 'userprofile') else False


class IsConfirmedDoctor(BasePermission):
    """
    Custom permission to only allow users with the role "doctor" and confirmed profile.
    """

    message = "You are not a confirmed doctor"

    def has_permission(self, request, view):
        # Check if the user is confirmed doctor
        if hasattr(request.user, 'userprofile'):
            if hasattr(request.user, 'doctorprofile'):
                return request.user.doctorprofile.is_confirmed
        return False



class IsSubscribed(BasePermission):
    message = "Your account is not active."

    def has_permission(self, request, view):
        try:
            expiry_date = request.user.userprofile.subscription_expiry
            current_time = timezone.now()
            if expiry_date > current_time:
                return True
            else:
                return False
        except AttributeError:
            return False
        except:
            return False



class IsDeliverySubscribed(BasePermission):
    message = "Your account is not active."

    def has_permission(self, request, view):
        try:
            expiry_date = request.user.laboratoryprofile.subscription_expiry
            current_time = timezone.now()
            if expiry_date > current_time:
                return True
            else:
                return False
        except AttributeError:
            return False
        except:
            return False