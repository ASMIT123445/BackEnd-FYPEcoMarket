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

    class Meta:
        model = User
        fields = ['username', 'first_name', 'last_name', 'email', 'password', 'password2', 'role']

    def create(self, validated_data):
        # Remove fields that User model does not accept
        password2 = validated_data.pop('password2', None)
        role = validated_data.pop('role', 'customer')
        

        # Create user
        user = User.objects.create_user(
            username=validated_data.get('username'),
            email=validated_data.get('email'),
            password=validated_data.get('password'),
            first_name=validated_data.get('first_name', ''),
            last_name=validated_data.get('last_name', '')
        )

        # Set extra fields if they exist on User model
        if hasattr(user, 'role'):
            user.role = role
        if hasattr(user, 'shop_name'):
            user.shop_name = shop_name
        if hasattr(user, 'phone'):
            user.phone = phone

        user.save()

        
    # Create CustomerProfile if role is customer
        if role == 'customer':
            CustomerProfile.objects.create(
                user=user,
                username=user.username,
                first_name=user.first_name,
                last_name=user.last_name,
                email=user.email,
                role=role
            )

            # Send email to customer
            send_mail(
                subject="Welcome to EcoMarket!",
                message=f"Hi {user.first_name},\n\nThank you for registering as a Customer on EcoMarket!",
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
                fail_silently=False
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
                shop_name=getattr(user, 'shop_name', '')
            )

            # Send email to seller
            send_mail(
                subject="Welcome to EcoMarket!",
                message=f"Hi {user.first_name},\n\nThank you for registering as a Seller on EcoMarket!",
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
                fail_silently=False
            )

        return user



# ---------------------------
# Profile Serializer for GET
# ---------------------------
class ProfileSerializer(serializers.ModelSerializer):
    role = serializers.CharField(source='profile.role')
    shop_name = serializers.CharField(source='profile.shop_name')
    phone = serializers.CharField(source='profile.phone')

    class Meta:
        model = User
        fields = ['username', 'email', 'role', 'shop_name', 'phone']


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
