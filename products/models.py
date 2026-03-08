from django.db import models
from django.contrib.auth.models import User
from django.utils.text import slugify
from django.core.validators import MinValueValidator, MaxValueValidator
# pylint: disable=no-member

class EcoCategory(models.Model):
    """Dynamic eco-friendly product categories managed by admin"""
    name = models.CharField(max_length=100, unique=True, help_text="Category name (e.g., 'Organic Products')")
    slug = models.SlugField(max_length=100, unique=True, help_text="URL-friendly version (e.g., 'organic_products')")
    description = models.TextField(blank=True, help_text="Description of this category")
    icon = models.CharField(max_length=50, blank=True, help_text="Icon class name (e.g., 'fa-leaf')")
    is_active = models.BooleanField(default=True, help_text="Whether this category is active")
    display_order = models.PositiveIntegerField(default=0, help_text="Order for displaying categories")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = "Eco Category"
        verbose_name_plural = "Eco Categories"
        ordering = ['display_order', 'name']
    
    def save(self, *args, **kwargs):
        if not self.slug:
            self.slug = slugify(self.name)
        super().save(*args, **kwargs)
    
    def __str__(self):
        return self.name

class ProductCategory(models.Model):
    """Product categories like Accessories, Kitchen Items, etc."""
    name = models.CharField(max_length=100, unique=True, help_text="Category name (e.g., 'Accessories')")
    slug = models.SlugField(max_length=100, unique=True, help_text="URL-friendly version (e.g., 'accessories')")
    description = models.TextField(blank=True, help_text="Description of this category")
    icon = models.CharField(max_length=50, blank=True, help_text="Icon class name (e.g., 'fa-heart')")
    is_active = models.BooleanField(default=True, help_text="Whether this category is active")
    display_order = models.PositiveIntegerField(default=0, help_text="Order for displaying categories")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = "Product Category"
        verbose_name_plural = "Product Categories"
        ordering = ['display_order', 'name']
    
    def save(self, *args, **kwargs):
        if not self.slug:
            self.slug = slugify(self.name)
        super().save(*args, **kwargs)
    
    def __str__(self):
        return self.name

class Product(models.Model):
    # Keep the old CATEGORY_CHOICES for backward compatibility during migration
    CATEGORY_CHOICES = [
        ('recycled_items', 'Recycled Items'),
        ('organic_products', 'Organic Products'),
        ('energy_efficient', 'Energy-Efficient'),
        ('reusable_household', 'Reusable Household'),
        ('handmade_ecocraft', 'Handmade Eco-Crafts'),
        ('sustainable_fashion', 'Sustainable Fashion'),
        ('eco_home_garden', 'Eco Home & Garden'),
    ]
    
    name = models.CharField(max_length=255)
    description = models.TextField()
    price = models.DecimalField(max_digits=10, decimal_places=2)
    
    # New foreign key to EcoCategory (nullable for migration)
    eco_category = models.ForeignKey(
        EcoCategory, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        help_text="Dynamic eco category"
    )
    
    # Product category (Accessories, Kitchen Items, etc.)
    product_category = models.ForeignKey(
        ProductCategory,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        help_text="Product category (Accessories, Kitchen Items, etc.)"
    )
    
    # Keep old category field for backward compatibility
    category = models.CharField(
        max_length=50, 
        choices=CATEGORY_CHOICES, 
        default='recycled_items', 
        help_text="Legacy category (will be migrated to eco_category)"
    )
    
    image = models.ImageField(upload_to='product_images/')
    rating = models.FloatField(default=0)
    stock = models.PositiveIntegerField(default=0, help_text="Number of items available in stock")
    seller = models.ForeignKey(User, on_delete=models.CASCADE, related_name='products', null=True, blank=True)
    is_validated = models.BooleanField(default=False, help_text="Admin verification for product quality and authenticity")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f'{self.name} - {"✓ Verified" if self.is_validated else "⏳ Pending"}'

    def get_category_display_name(self):
        """Get the human-readable category name"""
        if self.eco_category:
            return self.eco_category.name
        return dict(self.CATEGORY_CHOICES).get(self.category, self.category)
    
    def get_category_slug(self):
        """Get the category slug for filtering"""
        if self.eco_category:
            return self.eco_category.slug
        return self.category

    class Meta:
        ordering = ['-created_at']


class ProductRating(models.Model):
    """User ratings for products"""
    product = models.ForeignKey(Product, on_delete=models.CASCADE, related_name='ratings')
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='product_ratings')
    rating = models.IntegerField(
        validators=[MinValueValidator(1), MaxValueValidator(5)],
        help_text="Rating from 1 to 5 stars"
    )
    review = models.TextField(blank=True, help_text="Optional review text")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        unique_together = ('product', 'user')  # One rating per user per product
        ordering = ['-created_at']
        verbose_name = "Product Rating"
        verbose_name_plural = "Product Ratings"
    
    def __str__(self):
        return f"{self.user.username} - {self.product.name} - {self.rating}★"
