from django.contrib import admin
from .models import Product, EcoCategory, ProductCategory, ProductRating

@admin.register(EcoCategory)
class EcoCategoryAdmin(admin.ModelAdmin):
    list_display = ['name', 'slug', 'is_active', 'display_order', 'product_count', 'created_at']
    list_filter = ['is_active', 'created_at']
    search_fields = ['name', 'description']
    list_editable = ['is_active', 'display_order']
    prepopulated_fields = {'slug': ('name',)}
    readonly_fields = ['created_at', 'updated_at', 'product_count']
    
    fieldsets = (
        ('Category Information', {
            'fields': ('name', 'slug', 'description', 'icon')
        }),
        ('Display Settings', {
            'fields': ('is_active', 'display_order'),
            'description': 'Control how this category appears to users'
        }),
        ('Statistics', {
            'fields': ('product_count',),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    def product_count(self, obj):
        return obj.product_set.count()
    product_count.short_description = "Products in Category"
    
    def get_queryset(self, request):
        return super().get_queryset(request).prefetch_related('product_set')
    
    actions = ['activate_categories', 'deactivate_categories']
    
    def activate_categories(self, request, queryset):
        updated = queryset.update(is_active=True)
        self.message_user(request, f'{updated} categories activated.')
    activate_categories.short_description = "Activate selected categories"
    
    def deactivate_categories(self, request, queryset):
        updated = queryset.update(is_active=False)
        self.message_user(request, f'{updated} categories deactivated.')
    deactivate_categories.short_description = "Deactivate selected categories"

    @admin.register(ProductCategory)
    class ProductCategoryAdmin(admin.ModelAdmin):
        list_display = ['name', 'slug', 'is_active', 'display_order', 'product_count', 'created_at']
        list_filter = ['is_active', 'created_at']
        search_fields = ['name', 'description']
        list_editable = ['is_active', 'display_order']
        prepopulated_fields = {'slug': ('name',)}
        readonly_fields = ['created_at', 'updated_at', 'product_count']

        fieldsets = (
            ('Category Information', {
                'fields': ('name', 'slug', 'description', 'icon')
            }),
            ('Display Settings', {
                'fields': ('is_active', 'display_order'),
                'description': 'Control how this category appears to users'
            }),
            ('Statistics', {
                'fields': ('product_count',),
                'classes': ('collapse',)
            }),
            ('Timestamps', {
                'fields': ('created_at', 'updated_at'),
                'classes': ('collapse',)
            }),
        )

        def product_count(self, obj):
            return obj.product_set.count()
        product_count.short_description = "Products in Category"

        def get_queryset(self, request):
            return super().get_queryset(request).prefetch_related('product_set')

        actions = ['activate_categories', 'deactivate_categories']

        def activate_categories(self, request, queryset):
            updated = queryset.update(is_active=True)
            self.message_user(request, f'{updated} categories activated.')
        activate_categories.short_description = "Activate selected categories"

        def deactivate_categories(self, request, queryset):
            updated = queryset.update(is_active=False)
            self.message_user(request, f'{updated} categories deactivated.')
        deactivate_categories.short_description = "Deactivate selected categories"

@admin.register(Product)
class ProductAdmin(admin.ModelAdmin):
    list_display = ['name', 'seller', 'get_category_name', 'price', 'stock', 'is_validated', 'created_at', 'validation_status']
    list_filter = ['is_validated', 'eco_category', 'category', 'created_at', 'seller']
    search_fields = ['name', 'description', 'seller__username']
    list_editable = ['is_validated', 'stock']
    readonly_fields = ['created_at', 'updated_at']
    
    fieldsets = (
        ('Product Information', {
            'fields': ('name', 'description', 'eco_category', 'product_category', 'category', 'price', 'stock', 'image', 'rating', 'seller')
        }),
        ('Admin Verification', {
            'fields': ('is_validated',),
            'description': 'Admin can verify product quality and authenticity here'
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    def get_category_name(self, obj):
        return obj.get_category_display_name()
    get_category_name.short_description = "Category"
    
    def validation_status(self, obj):
        if obj.is_validated:
            return "✅ Verified"
        return "⏳ Pending Verification"
    validation_status.short_description = "Status"
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related('seller', 'eco_category')
    
    actions = ['mark_as_validated', 'mark_as_unvalidated']
    
    def mark_as_validated(self, request, queryset):
        updated = queryset.update(is_validated=True)
        self.message_user(request, f'{updated} products marked as validated.')
    mark_as_validated.short_description = "Mark selected products as validated"
    
    def mark_as_unvalidated(self, request, queryset):
        updated = queryset.update(is_validated=False)
        self.message_user(request, f'{updated} products marked as unvalidated.')
    mark_as_unvalidated.short_description = "Mark selected products as unvalidated"


@admin.register(ProductRating)
class ProductRatingAdmin(admin.ModelAdmin):
    list_display = ['product', 'user', 'rating', 'created_at']
    list_filter = ['rating', 'created_at']
    search_fields = ['product__name', 'user__username', 'review']
    readonly_fields = ['created_at', 'updated_at']
    
    fieldsets = (
        ('Rating Information', {
            'fields': ('product', 'user', 'rating', 'review')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
