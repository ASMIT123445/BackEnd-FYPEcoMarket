from django.db import models
from django.contrib.auth.models import User
import uuid
from django.utils import timezone
from datetime import timedelta

# pylint: disable=no-member

class Profile(models.Model):
    ROLE_CHOICES = (
        ("customer", "Customer"),
        ("seller", "Seller"),
    )

    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name="profile"
    )
    role = models.CharField(
        max_length=20,
        choices=ROLE_CHOICES
    )

    def __str__(self):
        return f"{self.user.username} ({self.role})"

class EmailVerification(models.Model):
    """Model to handle email verification for user registration"""
    email = models.EmailField()
    verification_code = models.CharField(max_length=6)  # 6-digit code instead of UUID
    user_data = models.JSONField()  # Store registration data temporarily
    role = models.CharField(max_length=20, choices=[('customer', 'Customer'), ('seller', 'Seller')])
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_verified = models.BooleanField(default=False)
    
    def save(self, *args, **kwargs):
        if not self.expires_at:
            self.expires_at = timezone.now() + timedelta(minutes=15)  # 15 minute expiry
        super().save(*args, **kwargs)
    
    def is_expired(self):
        return timezone.now() > self.expires_at
    
    def __str__(self):
        return f"Email verification for {self.email} ({self.role})"
    
class CustomerProfile(models.Model):
   
    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name="customer_user",
        null = True,
        blank=True
    )
    username = models.CharField(max_length = 255, null = True, blank=True )
    role = models.CharField(max_length=50, default="customer")
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    email = models.EmailField()
    address = models.TextField(blank=True, null=True, help_text="Full shipping address")
    green_points = models.IntegerField(default=0, help_text="Green Points balance for eco-friendly purchases")



    def save_from_user(self):
        """
        Populate this CustomerProfile from the linked User instance.
        """
        self.first_name = self.user.first_name
        self.last_name = self.user.last_name
        self.email = self.user.email
        # You can also populate role, shop_name, phone if available in user.profile
        if hasattr(self.user, "profile"):
            self.phone = getattr(self.user.profile, "phone", "")
            self.shop_name = getattr(self.user.profile, "shop_name", "")
        self.save()

    def __str__(self):
        return f"Customer: {self.user.username}"

class SellerProfile(models.Model):
    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name="seller_user",
        null = True,
        blank=True
    )
    username = models.CharField(max_length = 255, null = True, blank=True )
    role = models.CharField(max_length=50, default="seller")
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    email = models.EmailField()
    shop_name = models.CharField(max_length=100)
    address = models.TextField(blank=True, null=True, help_text="Full shipping address")
    is_validated = models.BooleanField(default=False, help_text="Admin verification for seller authenticity and documents")
    validation_date = models.DateTimeField(null=True, blank=True)
   

    def save_from_user(self):
        """
        Populate this SellerProfile from the linked User instance.
        """
        self.first_name = self.user.first_name
        self.last_name = self.user.last_name
        self.email = self.user.email
        # You can also populate role, shop_name, phone if available in user.profile
        if hasattr(self.user, "profile"):
            self.phone = getattr(self.user.profile, "phone", "")
            self.shop_name = getattr(self.user.profile, "shop_name", "")
        self.save()

    def __str__(self):
        return f"Seller: {self.user.username} - {'✓ Verified' if self.is_validated else '⏳ Pending'}"




# users/models.py
from django.db import models
from django.contrib.auth.models import User

# pylint: disable=no-member

class SellerOnboarding(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)

    # Section 1
    business_name = models.CharField(max_length=255, blank=True, null=True)
    business_type = models.CharField(max_length=50, blank=True, null=True)
    business_description = models.TextField(blank=True, null=True)

    # Section 2
    store_name = models.CharField(max_length=255, blank=True, null=True)
    store_category = models.CharField(max_length=50, blank=True, null=True)

    # Section 3
    owner_full_name = models.CharField(max_length=255, blank=True, null=True)
    phone_number = models.CharField(max_length=20, blank=True, null=True)
    business_address = models.TextField(blank=True, null=True)
    province = models.CharField(max_length=100, blank=True, null=True)
    pickup_address = models.TextField(blank=True, null=True)

    # Section 4
    id_proof = models.FileField(upload_to="id_proofs/", blank=True, null=True)
    business_document = models.FileField(upload_to="business_docs/", blank=True, null=True)

    # Section 5
    payment_method = models.CharField(max_length=50, blank=True, null=True)
    bank_account_name = models.CharField(max_length=255, blank=True, null=True)
    bank_account_number = models.CharField(max_length=50, blank=True, null=True)
    bank_name = models.CharField(max_length=255, blank=True, null=True)
    digital_wallet_number = models.CharField(max_length=50, blank=True, null=True)

    # Section 6
    agreed_terms = models.BooleanField(default=False)
    agreed_authenticity_policy = models.BooleanField(default=False)

    def __str__(self):
        return self.user.username   # ✅ shows username instead of object id


class GreenPointsTransaction(models.Model):
    """Track all green points transactions for customers"""
    TRANSACTION_TYPES = (
        ('earned', 'Points Earned'),
        ('redeemed', 'Points Redeemed'),
    )
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='green_points_transactions')
    points = models.IntegerField(help_text="Positive for earned, negative for redeemed")
    transaction_type = models.CharField(max_length=20, choices=TRANSACTION_TYPES)
    order = models.ForeignKey('orders.Order', on_delete=models.SET_NULL, null=True, blank=True, related_name='points_transactions')
    description = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']
        verbose_name = "Green Points Transaction"
        verbose_name_plural = "Green Points Transactions"
    
    def __str__(self):
        return f"{self.user.username} - {self.transaction_type} - {self.points} points"
