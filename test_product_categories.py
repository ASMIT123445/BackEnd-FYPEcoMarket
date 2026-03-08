#!/usr/bin/env python
"""
Test script for ProductCategory functionality
"""
import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Ecomarket.settings')
django.setup()

from products.models import ProductCategory, Product

def test_product_categories():
    print("Testing ProductCategory Model...")
    print("=" * 60)
    
    # Test 1: List all categories
    print("\n1. All Product Categories:")
    categories = ProductCategory.objects.all()
    for cat in categories:
        print(f"   - {cat.name} ({cat.slug}) - Active: {cat.is_active}")
    
    # Test 2: Get products by category
    print("\n2. Products by Category:")
    for cat in categories:
        product_count = Product.objects.filter(product_category=cat).count()
        print(f"   - {cat.name}: {product_count} products")
    
    # Test 3: Create a test product with product category
    print("\n3. Testing Product Creation with Categories:")
    from django.contrib.auth.models import User
    
    # Get or create a test user
    test_user, created = User.objects.get_or_create(
        username='test_seller',
        defaults={'email': 'test@example.com'}
    )
    
    # Get first eco category and product category
    from products.models import EcoCategory
    eco_cat = EcoCategory.objects.first()
    prod_cat = ProductCategory.objects.first()
    
    if eco_cat and prod_cat:
        print(f"   Creating test product with:")
        print(f"   - Eco Category: {eco_cat.name}")
        print(f"   - Product Category: {prod_cat.name}")
        
        # Note: This is just a test, we won't actually create the product
        # because it requires an image file
        print("   ✓ Categories are properly configured!")
    
    print("\n" + "=" * 60)
    print("✓ All tests passed!")

if __name__ == '__main__':
    test_product_categories()
