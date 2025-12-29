from django.db import models
from django.contrib.auth.models import User

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