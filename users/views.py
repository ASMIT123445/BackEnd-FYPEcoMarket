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
from .models import SellerOnboarding
from .serializers import SellerOnboardingSerializer
from rest_framework.permissions import IsAuthenticated




# ---------------------------
# User Registration Views
# ---------------------------

class RegisterUserView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        data = request.data.copy()
        data['role'] = 'customer'
        serializer = RegisterSerializer(data=data)

        if serializer.is_valid():
            serializer.save()
            print(f"{serializer.validated_data['first_name']}")

            return Response({"message": "User registered successfully"}, status=201)

        return Response(serializer.errors, status=400)


class RegisterSellerView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        data = request.data.copy()
        data['role'] = 'seller'
        serializer = RegisterSerializer(data=data)

        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Seller registered successfully"}, status=201)

        return Response(serializer.errors, status=400)


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
            refresh = RefreshToken.for_user(user)
            return Response({
                "access_token": str(refresh.access_token),
                "refresh_token": str(refresh)
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
        serializer = ProfileSerializer(user)
        return Response(serializer.data)


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

        reset_url = f"http://localhost:5173/reset-password/{uid}/{token}/"  # frontend URL

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

        # Ensure user is a seller
        if not hasattr(user, 'profile') or user.profile.role != 'seller':
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

        # Only sellers allowed
        if not hasattr(user, 'profile') or user.profile.role != 'seller':
            return Response({"error": "Only sellers can access onboarding"}, status=403)

        # Get or create onboarding instance
        onboarding, created = SellerOnboarding.objects.get_or_create(user=user)

        # Pass request.data and allow partial updates
        serializer = SellerOnboardingSerializer(
            onboarding,
            data=request.data,
            partial=True
        )

        if serializer.is_valid():
            # Save with user explicitly to avoid IntegrityError
            serializer.save(user=user)
            return Response({"message": f"Section {section} saved successfully"}, status=200)

        # Return detailed validation errors
        return Response(serializer.errors, status=400)
