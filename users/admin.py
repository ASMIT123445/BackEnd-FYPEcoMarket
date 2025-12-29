from django.contrib import admin
from .models import Profile, CustomerProfile, SellerProfile
from .models import SellerOnboarding
# Register your models here.

# admin.site.register(Profile)
admin.site.register(Profile)
   
@admin.register(CustomerProfile)
class CustomerProfileAdmin(admin.ModelAdmin):
    list_display = (
        "username",
        "role",
        "first_name",
        "last_name",
        "email",
    )


@admin.register(SellerProfile)
class SellerProfileAdmin(admin.ModelAdmin):
    list_display = (
        "username",
        "role",
        "first_name",
        "last_name",
        "email",
        "shop_name"
    )

admin.site.register(SellerOnboarding)
