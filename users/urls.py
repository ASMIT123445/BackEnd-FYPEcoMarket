from django.urls import path
from .views import ForgotPasswordView, ResetPasswordView, SellerOnboardingView

urlpatterns = [
    path('forgot-password/', ForgotPasswordView.as_view(), name='forgot-password'),
    path('reset-password/', ResetPasswordView.as_view(), name='reset-password'),

    # onboarding
    # path('seller/onboarding/', SellerOnboardingView.as_view(), name='seller-onboarding'),
    path('seller/onboarding/<int:section>/', SellerOnboardingView.as_view(), name='seller-onboarding'),
]
