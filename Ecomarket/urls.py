from django.contrib import admin
from django.urls import path, include  
from django.conf import settings
from django.conf.urls.static import static
from users.views import LoginView, ProfileView, RegisterSellerView, RegisterUserView, VerifyEmailView
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/register/', RegisterUserView.as_view()),
    path('api/login/', LoginView.as_view()),
    path('api/profile/', ProfileView.as_view()),
    path('api/auth/', include('users.urls')),  # includes seller onboarding etc.
    path('api/seller/register/', RegisterSellerView.as_view()),
    path('api/verify-email/', VerifyEmailView.as_view(), name='verify-email'),
    path('api/products/', include('products.urls')),  # products endpoints
    path('api/', include('orders.urls')),  # cart and orders endpoints
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),  # JWT refresh
]

# Serve media files during development
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
