from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        
        # Add custom claims
        token['username'] = user.username
        token['first_name'] = user.first_name
        token['last_name'] = user.last_name
        token['email'] = user.email
        
        # Get role from profile models
        role = 'customer'  # default
        try:
            if hasattr(user, 'customer_user'):
                role = user.customer_user.role
            elif hasattr(user, 'seller_user'):
                role = user.seller_user.role
            elif hasattr(user, 'profile'):
                role = user.profile.role
        except AttributeError:
            pass
        
        token['role'] = role
        
        return token

class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer