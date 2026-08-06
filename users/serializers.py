# users/serializers.py
# pylint: disable=no-member
from rest_framework import serializers
from django.contrib.auth.models import User
from .models import Profile, SellerOnboarding, CustomerProfile, SellerProfile
from django.core.mail import send_mail
from django.conf import settings

# ---------------------------
# User Registration Serializer
# ---------------------------
class RegisterSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(write_only=True)
    role = serializers.CharField(write_only=True)
    address = serializers.CharField(write_only=True, required=False, allow_blank=True)

    class Meta:
        model = User
        fields = ['username', 'first_name', 'last_name', 'email', 'password', 'password2', 'role', 'address']

    def create(self, validated_data):
        # Remove fields that User model does not accept
        password2 = validated_data.pop('password2', None)
        role = validated_data.pop('role', 'customer')
        address = validated_data.pop('address', '')
        

        # Create user
        user = User.objects.create_user(
            username=validated_data.get('username'),
            email=validated_data.get('email'),
            password=validated_data.get('password'),
            first_name=validated_data.get('first_name', ''),
            last_name=validated_data.get('last_name', '')
        )

        user.save()

        
    # Create CustomerProfile if role is customer
        if role == 'customer':
            CustomerProfile.objects.create(
                user=user,
                username=user.username,
                first_name=user.first_name,
                last_name=user.last_name,
                email=user.email,
                role=role,
                address=address
            )

        # Create SellerProfile if role is seller
        elif role == 'seller':
            SellerProfile.objects.create(
                user=user,
                username=user.username,
                first_name=user.first_name,
                last_name=user.last_name,
                email=user.email,
                role=role,
                shop_name='',  # Can be filled later in seller onboarding
                address=address
            )

        return user



# ---------------------------
# Profile Serializer for GET
# ---------------------------
class ProfileSerializer(serializers.ModelSerializer):
    role = serializers.SerializerMethodField()
    shop_name = serializers.SerializerMethodField()
    phone = serializers.SerializerMethodField()
    address = serializers.SerializerMethodField()
    is_verified = serializers.SerializerMethodField()
    profile_picture = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ['id', 'username', 'first_name', 'last_name', 'email', 'role', 'shop_name', 'phone', 'address', 'is_verified', 'is_staff', 'profile_picture']

    def get_profile_picture(self, obj):
        request = self.context.get('request')
        try:
            pic = obj.customer_user.profile_picture
            if pic and request:
                return request.build_absolute_uri(pic.url)
        except Exception:
            pass
        try:
            pic = obj.seller_user.profile_picture
            if pic and request:
                return request.build_absolute_uri(pic.url)
        except Exception:
            pass
        return None

    def get_role(self, obj):
        # Try to get role from different profile models using try-except
        try:
            if obj.seller_user:
                return obj.seller_user.role
        except:
            pass
        
        try:
            if obj.customer_user:
                return obj.customer_user.role
        except:
            pass
        
        try:
            if obj.profile:
                return obj.profile.role
        except:
            pass
        
        return 'customer'  # default

    def get_shop_name(self, obj):
        # Try to get shop_name from seller profile
        try:
            if obj.seller_user:
                return obj.seller_user.shop_name
        except:
            pass
        
        try:
            if obj.profile:
                return getattr(obj.profile, 'shop_name', '')
        except:
            pass
        
        return ''

    def get_phone(self, obj):
        # Try to get phone from profile models
        try:
            if obj.seller_user:
                return getattr(obj.seller_user, 'phone', '')
        except:
            pass
        
        try:
            if obj.customer_user:
                return getattr(obj.customer_user, 'phone', '')
        except:
            pass
        
        try:
            if obj.profile:
                return getattr(obj.profile, 'phone', '')
        except:
            pass
        
        return ''
    
    def get_is_verified(self, obj):
        try:
            if obj.seller_user:
                return obj.seller_user.is_validated
        except:
            pass
        return None  # None means not a seller

    def get_address(self, obj):
        # Try to get address from profile models using try-except for safety
        try:
            if obj.seller_user and obj.seller_user.address:
                return obj.seller_user.address
        except:
            pass
        
        try:
            if obj.customer_user and obj.customer_user.address:
                return obj.customer_user.address
        except:
            pass
        
        return ''


# ---------------------------
# Seller Onboarding Serializer
# ---------------------------
class SellerOnboardingSerializer(serializers.ModelSerializer):
    class Meta:
        model = SellerOnboarding
        exclude = ['user']  # user will be set in the view

    def validate(self, data):
        # Optional: Add validation per section here if needed
        return data

    def save(self, **kwargs):
        """
        Ensure 'user' is passed explicitly when saving.
        """
        user = kwargs.pop('user', None)
        if user is None:
            raise serializers.ValidationError("User must be provided for onboarding")
        onboarding_instance = super().save(**kwargs)
        onboarding_instance.user = user
        onboarding_instance.save()
        return onboarding_instance


from .models import GreenPointsTransaction

class GreenPointsTransactionSerializer(serializers.ModelSerializer):
    class Meta:
        model = GreenPointsTransaction
        fields = ['id', 'points', 'transaction_type', 'description', 'created_at']
        read_only_fields = ['id', 'created_at']
