from django.contrib import admin
from .models import Profile, CustomerProfile, SellerProfile
from .models import SellerOnboarding
# Register your models here.

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
    
    fieldsets = (
        ('Customer Information', {
            'fields': ('username', 'first_name', 'last_name', 'email', 'role', 'address')
        }),
    )
    
    search_fields = ['username', 'first_name', 'last_name', 'email']


@admin.register(SellerProfile)
class SellerProfileAdmin(admin.ModelAdmin):
    list_display = (
        "username",
        "role",
        "first_name",
        "last_name",
        "email",
        "shop_name",
        "is_validated",
        "validation_status"
    )
    list_filter = ['is_validated', 'validation_date']
    search_fields = ['username', 'first_name', 'last_name', 'email', 'shop_name']
    list_editable = ['is_validated']
    
    fieldsets = (
        ('Seller Information', {
            'fields': ('username', 'first_name', 'last_name', 'email', 'shop_name', 'role', 'address')
        }),
        ('Admin Verification', {
            'fields': ('is_validated', 'validation_date'),
            'description': 'Admin can verify seller authenticity and documents here'
        }),
    )
    
    def validation_status(self, obj):
        if obj.is_validated:
            return "✅ Verified"
        return "⏳ Pending Verification"
    validation_status.short_description = "Status"
    
    actions = ['mark_as_validated', 'mark_as_unvalidated']
    
    def mark_as_validated(self, request, queryset):
        from django.utils import timezone
        updated = queryset.update(is_validated=True, validation_date=timezone.now())
        self.message_user(request, f'{updated} sellers marked as validated.')
    mark_as_validated.short_description = "Mark selected sellers as validated"
    
    def mark_as_unvalidated(self, request, queryset):
        updated = queryset.update(is_validated=False, validation_date=None)
        self.message_user(request, f'{updated} sellers marked as unvalidated.')
    mark_as_unvalidated.short_description = "Mark selected sellers as unvalidated"

admin.site.register(SellerOnboarding)


from .models import GreenPointsTransaction

@admin.register(GreenPointsTransaction)
class GreenPointsTransactionAdmin(admin.ModelAdmin):
    list_display = ['user', 'points', 'transaction_type', 'description', 'created_at']
    list_filter = ['transaction_type', 'created_at']
    search_fields = ['user__username', 'description']
    readonly_fields = ['created_at']
    date_hierarchy = 'created_at'
