from rest_framework import serializers
from .models import Product, EcoCategory, ProductCategory, ProductRating
from django.contrib.auth.models import User

class EcoCategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = EcoCategory
        fields = ['id', 'name', 'slug', 'description', 'icon', 'is_active', 'display_order']

class ProductCategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = ProductCategory
        fields = ['id', 'name', 'slug', 'description', 'icon', 'is_active', 'display_order']

class ProductSerializer(serializers.ModelSerializer):
    seller_name = serializers.SerializerMethodField()
    image_url = serializers.SerializerMethodField()
    category_display = serializers.SerializerMethodField()
    eco_category_detail = EcoCategorySerializer(source='eco_category', read_only=True)
    product_category_detail = ProductCategorySerializer(source='product_category', read_only=True)
    
    class Meta:
        model = Product
        fields = [
            'id', 'name', 'description', 'price', 'category', 'category_display', 
            'eco_category', 'eco_category_detail', 'product_category', 'product_category_detail',
            'image', 'image_url', 'rating', 'seller', 'seller_name', 'is_validated', 
            'created_at', 'updated_at', 'stock'
        ]
        read_only_fields = ['seller', 'created_at', 'updated_at']
        
    def get_seller_name(self, obj):
        if obj.seller:
            return obj.seller.username
        return None
    
    def get_image_url(self, obj):
        if obj.image:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(obj.image.url)
            return obj.image.url
        return None
    
    def get_category_display(self, obj):
        return obj.get_category_display_name()
        
    def validate_price(self, value):
        if value <= 0:
            raise serializers.ValidationError("Price must be greater than 0")
        return value
        
    def validate_rating(self, value):
        if value < 0 or value > 5:
            raise serializers.ValidationError("Rating must be between 0 and 5")
        return value


class ProductRatingSerializer(serializers.ModelSerializer):
    user_name = serializers.SerializerMethodField()
    user_avatar = serializers.SerializerMethodField()
    
    class Meta:
        model = ProductRating
        fields = ['id', 'product', 'user', 'user_name', 'user_avatar', 'rating', 'review', 'created_at', 'updated_at']
        read_only_fields = ['product', 'user', 'created_at', 'updated_at']
    
    def get_user_name(self, obj):
        if obj.user.first_name and obj.user.last_name:
            return f"{obj.user.first_name} {obj.user.last_name}"
        return obj.user.username
    
    def get_user_avatar(self, obj):
        # Return initials for avatar
        if obj.user.first_name and obj.user.last_name:
            return f"{obj.user.first_name[0]}{obj.user.last_name[0]}".upper()
        return obj.user.username[:2].upper()
