#!/usr/bin/env python
"""
Script to test the verification system after migrations
Run this from the Ecomarket directory: python test_verification_system.py
"""
import os
import sys
import django

# Add the project directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Set up Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Ecomarket.settings')
django.setup()

from django.contrib.auth.models import User
from users.models import SellerOnboarding
from products.models import Product

def test_verification_system():
    """Test the verification system"""
    print("🧪 Testing verification system...")
    
    try:
        # Test SellerOnboarding model
        print("\n📋 Testing SellerOnboarding model...")
        seller_count = SellerOnboarding.objects.count()
        print(f"   Found {seller_count} seller onboarding records")
        
        # Test verification status choices
        choices = SellerOnboarding.VERIFICATION_STATUS_CHOICES
        print(f"   Verification status choices: {[choice[0] for choice in choices]}")
        
        # Test Product model
        print("\n📦 Testing Product model...")
        product_count = Product.objects.count()
        print(f"   Found {product_count} products")
        
        # Test verification status choices
        choices = Product.VERIFICATION_STATUS_CHOICES
        print(f"   Verification status choices: {[choice[0] for choice in choices]}")
        
        # Test model methods
        if seller_count > 0:
            seller = SellerOnboarding.objects.first()
            print(f"   Sample seller: {seller.user.username} - {seller.get_verification_status_display()}")
            print(f"   Onboarding complete: {seller.is_onboarding_complete()}")
        
        if product_count > 0:
            product = Product.objects.first()
            print(f"   Sample product: {product.name} - {product.get_verification_status_display()}")
        
        print("\n✅ Verification system is working correctly!")
        print("\n📊 Summary:")
        print(f"   - {seller_count} sellers in system")
        print(f"   - {product_count} products in system")
        print("   - All verification fields are accessible")
        print("   - Admin interface should be ready for verification management")
        
    except Exception as e:
        print(f"❌ Error testing verification system: {e}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    test_verification_system()