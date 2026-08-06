from django.urls import path
from .views import (
    ForgotPasswordView, ResetPasswordView, SellerOnboardingView,
    GreenPointsView, GreenPointsHistoryView, GreenPointsLeaderboardView, GoogleLoginView,
    ProfilePictureView, ForgotPasswordOTPView, ResetPasswordOTPView,
)

urlpatterns = [
    path('forgot-password/', ForgotPasswordView.as_view(), name='forgot-password'),
    path('reset-password/', ResetPasswordView.as_view(), name='reset-password'),

    # OTP-based password reset (new flow)
    path('forgot-password/otp/', ForgotPasswordOTPView.as_view(), name='forgot-password-otp'),
    path('reset-password/otp/', ResetPasswordOTPView.as_view(), name='reset-password-otp'),

    # onboarding
    path('seller/onboarding/<int:section>/', SellerOnboardingView.as_view(), name='seller-onboarding'),
    
    # Green Points
    path('green-points/', GreenPointsView.as_view(), name='green-points'),
    path('green-points/history/', GreenPointsHistoryView.as_view(), name='green-points-history'),
    path('green-points/leaderboard/', GreenPointsLeaderboardView.as_view(), name='green-points-leaderboard'),

    # Google OAuth
    path('google-login/', GoogleLoginView.as_view(), name='google-login'),

    # Profile picture
    path('profile-picture/', ProfilePictureView.as_view(), name='profile-picture'),
]


