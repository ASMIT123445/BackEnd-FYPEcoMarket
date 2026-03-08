from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import authentication, permissions
from django.contrib.auth.models import User
from .serializers import ProfileSerializer, RegisterSerializer
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.core.mail import send_mail
from django.conf import settings
from .models import SellerOnboarding, EmailVerification
from .serializers import SellerOnboardingSerializer
from rest_framework.permissions import IsAuthenticated
import random
import string
from django.utils import timezone




# ---------------------------
# Email Verification Views
# ---------------------------

class VerifyEmailView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        """Verify email using the confirmation code"""
        email = request.data.get('email')
        code = request.data.get('code')
        
        if not email or not code:
            return Response({
                "error": "Email and verification code are required."
            }, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            verification = EmailVerification.objects.get(
                email=email,
                verification_code=code,
                is_verified=False
            )
            
            if verification.is_expired():  
                return Response({
                    "error": "Verification code has expired. Please register again."
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Create the user account
            user_data = verification.user_data
            serializer = RegisterSerializer(data=user_data)
            
            if serializer.is_valid():
                user = serializer.save()
                
                # Mark verification as complete
                verification.is_verified = True
                verification.save()
                
                # Generate JWT tokens for auto-login with custom claims
                from .tokens import CustomTokenObtainPairSerializer
                refresh = CustomTokenObtainPairSerializer.get_token(user)
                
                return Response({
                    "message": "Email verified successfully! Your account has been created.",
                    "access": str(refresh.access_token),
                    "refresh": str(refresh),
                    "role": verification.role,
                    "redirect_to": "/seller/onboarding" if verification.role == "seller" else "/home"
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    "error": "Invalid user data. Please register again.",
                    "details": serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)
                
        except EmailVerification.DoesNotExist:
            return Response({
                "error": "Invalid email or verification code."
            }, status=status.HTTP_400_BAD_REQUEST)


# ---------------------------
# User Registration Views
# ---------------------------

class RegisterUserView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        """Register a customer user with email verification."""
        data = request.data.copy()
        data["role"] = "customer"

        # Validate the data first
        serializer = RegisterSerializer(data=data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        # Create email verification record with 6-digit code
        verification_code = ''.join(random.choices(string.digits, k=6))
        email_verification = EmailVerification.objects.create(
            email=data['email'],
            verification_code=verification_code,
            user_data=data,
            role='customer'
        )

        # Send verification email
        try:
            send_mail(
                subject="Verify Your Email - Ecomarket Registration",
                message=f"""
Hello {data.get('first_name', '')},

Thank you for registering with Ecomarket! 

Your verification code is: {verification_code}

Please enter this code on the verification page to complete your registration.

This code will expire in 15 minutes.

If you didn't create an account, please ignore this email.

Best regards,
Ecomarket Team
                """,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[data['email']],
                fail_silently=False
            )
            
            return Response({
                "message": "Registration initiated. Please check your email for the verification code.",
                "verification_required": True,
                "email": data['email']  # Send email back for verification form
            }, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            # Clean up verification record if email fails
            email_verification.delete()
            return Response({
                "error": "Failed to send verification email. Please try again."
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class RegisterSellerView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        """Register a seller user with email verification."""
        data = request.data.copy()
        data['role'] = 'seller'

        # Validate the data first
        serializer = RegisterSerializer(data=data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        # Create email verification record with 6-digit code
        verification_code = ''.join(random.choices(string.digits, k=6))
        email_verification = EmailVerification.objects.create(
            email=data['email'],
            verification_code=verification_code,
            user_data=data,
            role='seller'
        )

        # Send verification email
        try:
            send_mail(
                subject="Verify Your Email - Ecomarket Seller Registration",
                message=f"""
Hello {data.get('first_name', '')},

Thank you for registering as a seller with Ecomarket! 

Your verification code is: {verification_code}

Please enter this code on the verification page to complete your registration.

After verification, you'll be able to complete your seller onboarding process.

This code will expire in 15 minutes.

If you didn't create an account, please ignore this email.

Best regards,
Ecomarket Team
                """,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[data['email']],
                fail_silently=False
            )
            
            return Response({
                "message": "Registration initiated. Please check your email for the verification code.",
                "verification_required": True,
                "email": data['email']  # Send email back for verification form
            }, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            # Clean up verification record if email fails
            email_verification.delete()
            return Response({
                "error": "Failed to send verification email. Please try again."
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# class RegisterSellerView(APIView):
#     permission_classes = [AllowAny]

#     def post(self, request):
#         data = request.data.copy()
#         data['role'] = 'seller'
#         serializer = RegisterSerializer(data=data)

#         if serializer.is_valid():
#             serializer.save()
#             return Response({"message": "Seller registered successfully"}, status=201)

#         return Response(serializer.errors, status=400)


# ---------------------------
# Login View
# ---------------------------
class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')

        if not username or not password:
            return Response({"error": "Username and password required"}, status=400)

        user = User.objects.filter(username=username).first()
        if user and user.check_password(password):
            # Use custom token serializer to include profile data
            from .tokens import CustomTokenObtainPairSerializer
            
            # Create token with custom claims
            refresh = CustomTokenObtainPairSerializer.get_token(user)
            
            return Response({
                "access": str(refresh.access_token),
                "refresh": str(refresh)
            })
        return Response({"message": "Invalid credentials"}, status=status.HTTP_400_BAD_REQUEST)



# ---------------------------
# Profile View
# ---------------------------
    
    # pylint: disable=no-member
class ProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        serializer = ProfileSerializer(user, context={'request': request})
        return Response(serializer.data)
    
    def put(self, request):
        """Update user profile information"""
        try:
            user = request.user
            data = request.data
            
            # Update basic user fields
            if 'first_name' in data:
                user.first_name = data['first_name']
            if 'last_name' in data:
                user.last_name = data['last_name']
            if 'email' in data:
                user.email = data['email']
            if 'username' in data:
                user.username = data['username']
            
            user.save()
            
            # Handle role and profile updates
            from .models import CustomerProfile, SellerProfile
            new_role = data.get('role', 'customer')
            
            # Check current profile type using try-except for safety
            has_customer_profile = False
            has_seller_profile = False
            
            try:
                if user.customer_user:
                    has_customer_profile = True
            except CustomerProfile.DoesNotExist:
                pass
            
            try:
                if user.seller_user:
                    has_seller_profile = True
            except SellerProfile.DoesNotExist:
                pass
            
            if new_role == 'customer':
                # If changing to customer or updating customer profile
                if has_customer_profile:
                    # Update existing customer profile
                    profile = user.customer_user
                    profile.username = data.get('username', user.username)
                    profile.first_name = user.first_name
                    profile.last_name = user.last_name
                    profile.email = user.email
                    profile.role = new_role
                    if 'address' in data:
                        profile.address = data['address']
                    profile.save()
                else:
                    # Create new customer profile (and remove seller profile if exists)
                    if has_seller_profile:
                        user.seller_user.delete()
                    
                    CustomerProfile.objects.create(
                        user=user,
                        username=data.get('username', user.username),
                        first_name=user.first_name,
                        last_name=user.last_name,
                        email=user.email,
                        role=new_role,
                        address=data.get('address', '')
                    )
                    
            elif new_role == 'seller':
                # If changing to seller or updating seller profile
                if has_seller_profile:
                    # Update existing seller profile
                    profile = user.seller_user
                    profile.username = data.get('username', user.username)
                    profile.first_name = user.first_name
                    profile.last_name = user.last_name
                    profile.email = user.email
                    profile.role = new_role
                    if 'address' in data:
                        profile.address = data['address']
                    profile.save()
                else:
                    # Create new seller profile (and remove customer profile if exists)
                    if has_customer_profile:
                        user.customer_user.delete()
                    
                    SellerProfile.objects.create(
                        user=user,
                        username=data.get('username', user.username),
                        first_name=user.first_name,
                        last_name=user.last_name,
                        email=user.email,
                        role=new_role,
                        shop_name=data.get('shop_name', ''),
                        address=data.get('address', '')
                    )
            
            # Return updated profile
            serializer = ProfileSerializer(user, context={'request': request})
            return Response({
                'message': 'Profile updated successfully',
                'profile': serializer.data
            })
            
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ---------------------------
# Password Reset Views
# ---------------------------

class ForgotPasswordView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        if not email:
            return Response({"error": "Email is required"}, status=400)

        user = User.objects.filter(email=email).first()
        if not user:
            return Response({"error": "User with this email does not exist"}, status=404)

        token_generator = PasswordResetTokenGenerator()
        token = token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))

        reset_url = f"http://localhost:5173/reset-password/{uid}/{token}/"  # Updated to correct port

        send_mail(
            "Reset your password",
            f"Click the link to reset your password: {reset_url}",
            settings.DEFAULT_FROM_EMAIL,
            [email],
            fail_silently=False
        )

        return Response({"message": "Password reset link sent to email"}, status=200)


# pylint: disable=no-member

class ResetPasswordView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        uid = request.data.get('uid')
        token = request.data.get('token')
        password = request.data.get('password')
        password2 = request.data.get('password2')

        if password != password2:
            return Response({"error": "Passwords must match"}, status=400)

        try:
            user_id = force_str(urlsafe_base64_decode(uid))
            user = User.objects.get(pk=user_id)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response({"error": "Invalid uid"}, status=400)

        token_generator = PasswordResetTokenGenerator()
        if not token_generator.check_token(user, token):
            return Response({"error": "Invalid or expired token"}, status=400)

        user.set_password(password)
        user.save()

        return Response({"message": "Password reset successful"}, status=200)

# pylint: disable=no-member


class SellerOnboardingView(APIView):
    permission_classes = [IsAuthenticated] 

    def get(self, request, section):
        """
        GET onboarding data for the logged-in seller
        """
        user = request.user

        # Check if user is a seller by looking for SellerProfile
        if not hasattr(user, 'seller_user'):
            return Response({"error": "Only sellers can access onboarding"}, status=403)

        onboarding = SellerOnboarding.objects.filter(user=user).first()
        if not onboarding:
            return Response({"message": "No onboarding data found"}, status=404)

        serializer = SellerOnboardingSerializer(onboarding)
        return Response(serializer.data)

    def post(self, request, section):
        """
        Create or update seller onboarding section
        """
        user = request.user

        # Check if user is a seller by looking for SellerProfile
        if not hasattr(user, 'seller_user'):
            return Response({"error": "Only sellers can access onboarding"}, status=403)

        # Get or create onboarding instance
        onboarding, created = SellerOnboarding.objects.get_or_create(user=user)

        # Pass request.data and allow partial updates
        serializer = SellerOnboardingSerializer(
            onboarding,
            data=request.data,
            partial=True
        )

        print(request.user)
        print(request.auth)


        if serializer.is_valid():
            # Save with user explicitly to avoid IntegrityError
            serializer.save(user=user)
            return Response({"message": f"Section {section} saved successfully"}, status=200)

        # Return detailed validation errors
        return Response(serializer.errors, status=400)

# class SellerOnboardingView(APIView):
#     permission_classes = [IsAuthenticated]

#     def get(self, request, section):
#         user = request.user

#         if user.role != "seller":
#             return Response({"error": "Only sellers can access onboarding"}, status=403)

#         onboarding = SellerOnboarding.objects.filter(user=user).first()
#         if not onboarding:
#             return Response({"message": "No onboarding data found"}, status=404)

#         serializer = SellerOnboardingSerializer(onboarding)
#         return Response(serializer.data)

#     def post(self, request, section):
#         user = request.user

#         if user.role != "seller":
#             return Response({"error": "Only sellers can access onboarding"}, status=403)

#         onboarding, _ = SellerOnboarding.objects.get_or_create(user=user)

#         serializer = SellerOnboardingSerializer(
#             onboarding,
#             data=request.data,
#             partial=True
#         )

#         if serializer.is_valid():
#             serializer.save(user=user)
#             return Response(
#                 {"message": f"Section {section} saved successfully"},
#                 status=200
#             )

#         return Response(serializer.errors, status=400)





from .models import GreenPointsTransaction
from .serializers import GreenPointsTransactionSerializer

class GreenPointsView(APIView):
    """Get user's green points balance"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        try:
            customer_profile = request.user.customer_user
            return Response({
                'balance': customer_profile.green_points,
                'username': request.user.username
            })
        except Exception as e:
            return Response({
                'balance': 0,
                'error': 'Customer profile not found'
            }, status=status.HTTP_404_NOT_FOUND)

class GreenPointsHistoryView(APIView):
    """Get user's green points transaction history"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        transactions = GreenPointsTransaction.objects.filter(user=request.user).order_by('-created_at')[:20]
        serializer = GreenPointsTransactionSerializer(transactions, many=True)
        return Response(serializer.data)
