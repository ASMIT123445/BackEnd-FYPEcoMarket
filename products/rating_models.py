from django.db import models
from django.contrib.auth.models import User
from .models import Product
from django.core.validators import MinValueValidator, MaxValueValidator

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
