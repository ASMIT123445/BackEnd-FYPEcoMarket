from django.contrib import admin
from django.urls import path, include  
from django.conf import settings
from django.conf.urls.static import static
from users.views import LoginView, ProfileView, RegisterSellerView, RegisterUserView

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/register/', RegisterUserView.as_view()),
    path('api/login/', LoginView.as_view()),
    path('api/profile/', ProfileView.as_view()),
    path('api/auth/', include('users.urls')),  # includes seller onboarding etc.
    path('api/seller/register/', RegisterSellerView.as_view()),
]

# Serve media files during development
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
