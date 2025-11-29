from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import authentication, permissions
from django.contrib.auth.models import User
from .serializers import RegisterSerializer
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.core.mail import send_mail
from django.conf import settings



class RegisterSellerView(APIView):
    def post(self, request):
        data = request.data.copy()
        data['role'] = 'seller'
        serializer = RegisterSerializer(data=data)

        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Seller registered successfully"}, status=201)

        return Response(serializer.errors, status=400)

class RegisterUserView(APIView):
    def post(self, request):
        data = request.data.copy()
        data['role'] = 'customer'
        serializer = RegisterSerializer(data=data)

        if serializer.is_valid():
            serializer.save()
            return Response({"message": "User registered successfully"}, status=201)

        return Response(serializer.errors, status=400)

    
class LoginView(APIView):
    def post(self, request):
        data = request.data
        username = data.get('username')
        password = data.get('password')
        user = User.objects.filter(username = username).first()
        if user and user.check_password(password):
            refresh = RefreshToken.for_user(user)
            return Response({
                "access_token" : str(refresh.access_token),
                "refresh_token" : str(refresh)
            })
        return Response({"message" : "Invalid credential"}, status=status.HTTP_400_BAD_REQUEST)
    
class ProfileView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        user = request.user
        serializer = RegisterSerializer(user)
        return Response(serializer.data)

class ForgotPasswordView(APIView):
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

        reset_url = f"http://localhost:3000/reset-password/{uid}/{token}/"  # frontend URL

        # Send email (console for now)
        send_mail(
            "Reset your password",
            f"Click the link to reset your password: {reset_url}",
            settings.DEFAULT_FROM_EMAIL,
            [email],
            fail_silently=False
        )

        return Response({"message": "Password reset link sent to email"}, status=200)

class ResetPasswordView(APIView):
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
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):  # pylint: disable=no-member
            return Response({"error": "Invalid uid"}, status=400)

        token_generator = PasswordResetTokenGenerator()
        if not token_generator.check_token(user, token):
            return Response({"error": "Invalid or expired token"}, status=400)

        user.set_password(password)
        user.save()

        return Response({"message": "Password reset successful"}, status=200)
