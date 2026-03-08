from django.urls import path
from .views import (
    ForgotPasswordView, ResetPasswordView, SellerOnboardingView,
    GreenPointsView, GreenPointsHistoryView
)

urlpatterns = [
    path('forgot-password/', ForgotPasswordView.as_view(), name='forgot-password'),
    path('reset-password/', ResetPasswordView.as_view(), name='reset-password'),

    # onboarding
    # path('seller/onboarding/', SellerOnboardingView.as_view(), name='seller-onboarding'),
    path('seller/onboarding/<int:section>/', SellerOnboardingView.as_view(), name='seller-onboarding'),
    
    # Green Points
    path('green-points/', GreenPointsView.as_view(), name='green-points'),
    path('green-points/history/', GreenPointsHistoryView.as_view(), name='green-points-history'),
]
