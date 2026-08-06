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
from django.core.mail import send_mail, EmailMultiAlternatives
from django.conf import settings
from .models import SellerOnboarding, EmailVerification
from .serializers import SellerOnboardingSerializer
from rest_framework.permissions import IsAuthenticated
import random
import string
from django.utils import timezone


# ---------------------------
# Email Helper Functions
# ---------------------------

def send_otp_email(recipient_email, first_name, otp_code, is_seller=False):
    """Send a styled HTML OTP verification email."""
    role_label = "Seller" if is_seller else "Customer"
    subject = f"Verify Your Email – Ecomarket {'Seller ' if is_seller else ''}Registration"

    plain_text = (
        f"Hello {first_name},\n\n"
        f"Your Ecomarket verification code is: {otp_code}\n\n"
        f"This code expires in 15 minutes.\n\n"
        f"If you didn't request this, please ignore this email.\n\n"
        f"– The Ecomarket Team"
    )

    html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Email Verification</title>
</head>
<body style="margin:0;padding:0;background-color:#f0f4f0;font-family:'Segoe UI',Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#f0f4f0;padding:40px 0;">
    <tr>
      <td align="center">
        <table width="560" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 4px 20px rgba(0,0,0,0.08);">

          <!-- Header -->
          <tr>
            <td style="background:linear-gradient(135deg,#2e7d32,#66bb6a);padding:36px 40px;text-align:center;">
              <h1 style="margin:0;color:#ffffff;font-size:26px;font-weight:700;letter-spacing:1px;">🌿 Ecomarket</h1>
              <p style="margin:6px 0 0;color:#c8e6c9;font-size:14px;">Sustainable Shopping, Verified Identity</p>
            </td>
          </tr>

          <!-- Body -->
          <tr>
            <td style="padding:40px 40px 32px;">
              <h2 style="margin:0 0 8px;color:#1b5e20;font-size:20px;">Hello, {first_name}! 👋</h2>
              <p style="margin:0 0 24px;color:#555;font-size:15px;line-height:1.6;">
                Thanks for signing up as a <strong>{role_label}</strong> on Ecomarket.
                Use the verification code below to confirm your email address and activate your account.
              </p>

              <!-- OTP Box -->
              <table width="100%" cellpadding="0" cellspacing="0">
                <tr>
                  <td align="center" style="padding:8px 0 28px;">
                    <div style="display:inline-block;background:#f1f8e9;border:2px dashed #66bb6a;border-radius:12px;padding:20px 48px;">
                      <p style="margin:0 0 4px;color:#388e3c;font-size:12px;font-weight:600;letter-spacing:2px;text-transform:uppercase;">Your OTP Code</p>
                      <p style="margin:0;color:#1b5e20;font-size:42px;font-weight:800;letter-spacing:10px;">{otp_code}</p>
                    </div>
                  </td>
                </tr>
              </table>

              <!-- Expiry notice -->
              <table width="100%" cellpadding="0" cellspacing="0">
                <tr>
                  <td style="background:#fff8e1;border-left:4px solid #ffc107;border-radius:4px;padding:12px 16px;margin-bottom:24px;">
                    <p style="margin:0;color:#795548;font-size:13px;">
                      ⏱ This code expires in <strong>15 minutes</strong>. Do not share it with anyone.
                    </p>
                  </td>
                </tr>
              </table>

              <p style="margin:24px 0 0;color:#777;font-size:13px;line-height:1.6;">
                If you didn't create an Ecomarket account, you can safely ignore this email.
              </p>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="background:#f9fbe7;padding:20px 40px;text-align:center;border-top:1px solid #e8f5e9;">
              <p style="margin:0;color:#aaa;font-size:12px;">
                © 2025 Ecomarket · Sustainable Shopping Platform<br/>
                This is an automated message — please do not reply.
              </p>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>
"""

    msg = EmailMultiAlternatives(
        subject=subject,
        body=plain_text,
        from_email=settings.DEFAULT_FROM_EMAIL,
        to=[recipient_email],
    )
    msg.attach_alternative(html_content, "text/html")
    msg.send(fail_silently=False)


def send_password_reset_email(recipient_email, first_name, reset_url):
    """Send a styled HTML password reset email."""
    subject = "Reset Your Password – Ecomarket"

    plain_text = (
        f"Hello {first_name},\n\n"
        f"We received a request to reset your Ecomarket password.\n\n"
        f"Click the link below to reset it (valid for 1 hour):\n{reset_url}\n\n"
        f"If you didn't request this, please ignore this email.\n\n"
        f"– The Ecomarket Team"
    )

    html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Password Reset</title>
</head>
<body style="margin:0;padding:0;background-color:#f0f4f0;font-family:'Segoe UI',Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#f0f4f0;padding:40px 0;">
    <tr>
      <td align="center">
        <table width="560" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 4px 20px rgba(0,0,0,0.08);">

          <!-- Header -->
          <tr>
            <td style="background:linear-gradient(135deg,#2e7d32,#66bb6a);padding:36px 40px;text-align:center;">
              <h1 style="margin:0;color:#ffffff;font-size:26px;font-weight:700;letter-spacing:1px;">🌿 Ecomarket</h1>
              <p style="margin:6px 0 0;color:#c8e6c9;font-size:14px;">Sustainable Shopping, Verified Identity</p>
            </td>
          </tr>

          <!-- Body -->
          <tr>
            <td style="padding:40px 40px 32px;">
              <h2 style="margin:0 0 8px;color:#1b5e20;font-size:20px;">Password Reset Request 🔐</h2>
              <p style="margin:0 0 24px;color:#555;font-size:15px;line-height:1.6;">
                Hello <strong>{first_name}</strong>, we received a request to reset the password for your Ecomarket account.
                Click the button below to choose a new password.
              </p>

              <!-- CTA Button -->
              <table width="100%" cellpadding="0" cellspacing="0">
                <tr>
                  <td align="center" style="padding:8px 0 28px;">
                    <a href="{reset_url}"
                       style="display:inline-block;background:linear-gradient(135deg,#2e7d32,#66bb6a);color:#ffffff;text-decoration:none;font-size:16px;font-weight:600;padding:14px 40px;border-radius:8px;letter-spacing:0.5px;">
                      Reset My Password
                    </a>
                  </td>
                </tr>
              </table>

              <!-- Fallback link -->
              <p style="margin:0 0 8px;color:#777;font-size:13px;">Or copy and paste this link into your browser:</p>
              <p style="margin:0 0 24px;word-break:break-all;">
                <a href="{reset_url}" style="color:#388e3c;font-size:13px;">{reset_url}</a>
              </p>

              <!-- Warning notice -->
              <table width="100%" cellpadding="0" cellspacing="0">
                <tr>
                  <td style="background:#fff8e1;border-left:4px solid #ffc107;border-radius:4px;padding:12px 16px;">
                    <p style="margin:0;color:#795548;font-size:13px;">
                      ⏱ This link expires in <strong>1 hour</strong>. If you didn't request a password reset, you can safely ignore this email — your password will remain unchanged.
                    </p>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="background:#f9fbe7;padding:20px 40px;text-align:center;border-top:1px solid #e8f5e9;">
              <p style="margin:0;color:#aaa;font-size:12px;">
                © 2025 Ecomarket · Sustainable Shopping Platform<br/>
                This is an automated message — please do not reply.
              </p>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>
"""

    msg = EmailMultiAlternatives(
        subject=subject,
        body=plain_text,
        from_email=settings.DEFAULT_FROM_EMAIL,
        to=[recipient_email],
    )
    msg.attach_alternative(html_content, "text/html")
    msg.send(fail_silently=False)


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
            send_otp_email(
                recipient_email=data['email'],
                first_name=data.get('first_name', 'there'),
                otp_code=verification_code,
                is_seller=False,
            )

            return Response({
                "message": "Registration initiated. Please check your email for the verification code.",
                "verification_required": True,
                "email": data['email']
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
            send_otp_email(
                recipient_email=data['email'],
                first_name=data.get('first_name', 'there'),
                otp_code=verification_code,
                is_seller=True,
            )

            return Response({
                "message": "Registration initiated. Please check your email for the verification code.",
                "verification_required": True,
                "email": data['email']
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
        username = request.data.get('username')

        if not email:
            return Response({"error": "Email is required"}, status=400)

        # Find user by email
        user = User.objects.filter(email=email).first()
        if not user:
            return Response({"error": "No account found with this email address"}, status=404)

        # If username provided, verify it matches the account with this email
        if username:
            if user.username.lower() != username.lower():
                return Response({"error": "Username and email do not match the same account"}, status=400)

        token_generator = PasswordResetTokenGenerator()
        token = token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))

        reset_url = f"http://localhost:5173/reset-password/{uid}/{token}/"

        send_password_reset_email(
            recipient_email=email,
            first_name=user.first_name or user.username,
            reset_url=reset_url,
        )

        return Response({"message": "Password reset link sent to email"}, status=200)


class ForgotPasswordOTPView(APIView):
    """
    Step 1: Verify username + email match, then send OTP.
    POST { username, email } → sends OTP, returns { message, email }
    """
    permission_classes = [AllowAny]

    def post(self, request):
        username = request.data.get('username', '').strip()
        email = request.data.get('email', '').strip()

        if not username:
            return Response({"error": "Username is required"}, status=400)
        if not email:
            return Response({"error": "Email is required"}, status=400)

        # Find user by username
        user = User.objects.filter(username=username).first()
        if not user:
            return Response({"error": "No account found with this username"}, status=404)

        # Verify email matches
        if user.email.lower() != email.lower():
            return Response({"error": "Username and email do not match the same account"}, status=400)

        # Generate 6-digit OTP and store in EmailVerification (reuse model)
        otp = ''.join(random.choices(string.digits, k=6))

        # Delete any existing unverified reset OTPs for this email
        EmailVerification.objects.filter(email=email, role='password_reset').delete()

        EmailVerification.objects.create(
            email=email,
            verification_code=otp,
            user_data={'username': username},
            role='password_reset',
        )

        # Send OTP email
        try:
            send_otp_email(
                recipient_email=email,
                first_name=user.first_name or user.username,
                otp_code=otp,
                is_seller=False,
            )
        except Exception as e:
            return Response({"error": "Failed to send OTP email. Please try again."}, status=500)

        return Response({
            "message": "OTP sent to your email. Enter it to reset your password.",
            "email": email,
        }, status=200)


class ResetPasswordOTPView(APIView):
    """
    Step 2: Verify OTP + set new password.
    POST { username, email, otp, password, password2 }
    """
    permission_classes = [AllowAny]

    def post(self, request):
        username = request.data.get('username', '').strip()
        email = request.data.get('email', '').strip()
        otp = request.data.get('otp', '').strip()
        password = request.data.get('password', '')
        password2 = request.data.get('password2', '')

        if not all([username, email, otp, password, password2]):
            return Response({"error": "All fields are required"}, status=400)

        if password != password2:
            return Response({"error": "Passwords do not match"}, status=400)

        if len(password) < 4:
            return Response({"error": "Password must be at least 4 characters"}, status=400)

        # Verify OTP
        try:
            verification = EmailVerification.objects.get(
                email=email,
                verification_code=otp,
                role='password_reset',
                is_verified=False,
            )
        except EmailVerification.DoesNotExist:
            return Response({"error": "Invalid OTP. Please check and try again."}, status=400)

        if verification.is_expired():
            verification.delete()
            return Response({"error": "OTP has expired. Please request a new one."}, status=400)

        # Verify username still matches
        user = User.objects.filter(username=username, email__iexact=email).first()
        if not user:
            return Response({"error": "Account not found"}, status=404)

        # Reset password
        user.set_password(password)
        user.save()

        # Mark OTP as used
        verification.is_verified = True
        verification.save()

        return Response({"message": "Password reset successful! You can now log in."}, status=200)


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





class ProfilePictureView(APIView):
    """Upload or update profile picture"""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        picture = request.FILES.get('profile_picture')
        if not picture:
            return Response({'error': 'No image provided'}, status=status.HTTP_400_BAD_REQUEST)

        # Save to whichever profile exists
        from .models import CustomerProfile, SellerProfile
        saved = False
        try:
            profile = user.customer_user
            profile.profile_picture = picture
            profile.save()
            saved = True
        except Exception:
            pass

        if not saved:
            try:
                profile = user.seller_user
                profile.profile_picture = picture
                profile.save()
                saved = True
            except Exception:
                pass

        if not saved:
            return Response({'error': 'No profile found for user'}, status=status.HTTP_404_NOT_FOUND)

        serializer = ProfileSerializer(user, context={'request': request})
        return Response({'message': 'Profile picture updated', 'profile': serializer.data})


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


class GreenPointsLeaderboardView(APIView):
    """
    Public leaderboard — top users ranked by all-time green points earned.
    Uses CustomerProfile.green_points (current balance) as the ranking metric.
    Also annotates the requesting user's rank if authenticated.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from .models import CustomerProfile
        from django.db.models import F

        # Top 50 customers ordered by green_points descending
        top_profiles = (
            CustomerProfile.objects
            .select_related('user')
            .filter(green_points__gt=0)
            .order_by('-green_points')[:50]
        )

        leaderboard = []
        for rank, profile in enumerate(top_profiles, start=1):
            name = profile.first_name or profile.user.username
            if profile.last_name:
                name = f"{name} {profile.last_name[0]}."  # privacy: only first letter of last name
            leaderboard.append({
                'rank': rank,
                'username': profile.user.username,
                'display_name': name,
                'green_points': profile.green_points,
                'is_current_user': profile.user == request.user,
            })

        # Find current user's rank even if outside top 50
        current_user_rank = None
        try:
            current_profile = request.user.customer_user
            higher_count = CustomerProfile.objects.filter(
                green_points__gt=current_profile.green_points
            ).count()
            current_user_rank = higher_count + 1
            current_user_points = current_profile.green_points
        except Exception:
            current_user_points = 0

        return Response({
            'leaderboard': leaderboard,
            'current_user_rank': current_user_rank,
            'current_user_points': current_user_points,
        })


# ---------------------------
# Google OAuth Login
# ---------------------------
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests

GOOGLE_CLIENT_ID = '837983958389-8j7llq8185rppnhg6huau6nmrojbf1vm.apps.googleusercontent.com'

class GoogleLoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        access_token = request.data.get('access_token')
        if not access_token:
            return Response({'error': 'Google access_token is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Fetch user info from Google using the access token
            import requests as req
            userinfo_response = req.get(
                'https://www.googleapis.com/oauth2/v3/userinfo',
                headers={'Authorization': f'Bearer {access_token}'},
                timeout=10
            )
            if userinfo_response.status_code != 200:
                return Response({'error': 'Failed to fetch Google user info'}, status=status.HTTP_400_BAD_REQUEST)
            idinfo = userinfo_response.json()
        except Exception as e:
            return Response({'error': f'Google verification failed: {str(e)}'}, status=status.HTTP_400_BAD_REQUEST)

        google_email = idinfo.get('email')
        first_name   = idinfo.get('given_name', '')
        last_name    = idinfo.get('family_name', '')

        if not google_email:
            return Response({'error': 'Could not retrieve email from Google'}, status=status.HTTP_400_BAD_REQUEST)

        # Find or create the user
        user, created = User.objects.get_or_create(
            email=google_email,
            defaults={
                'username': google_email.split('@')[0],
                'first_name': first_name,
                'last_name': last_name,
            }
        )

        # If username already taken, make it unique
        if created:
            base_username = google_email.split('@')[0]
            username = base_username
            counter = 1
            while User.objects.filter(username=username).exclude(pk=user.pk).exists():
                username = f'{base_username}{counter}'
                counter += 1
            user.username = username
            user.set_unusable_password()
            user.save()

        # Issue JWT tokens with custom claims (username, role, etc.)
        from .tokens import CustomTokenObtainPairSerializer
        refresh = CustomTokenObtainPairSerializer.get_token(user)
        access_jwt = refresh.access_token

        return Response({
            'access': str(access_jwt),
            'refresh': str(refresh),
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
            },
            'created': created,
        }, status=status.HTTP_200_OK)
