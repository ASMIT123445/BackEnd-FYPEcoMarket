#!/usr/bin/env python
"""
Script to populate default product categories
Run with: python populate_product_categories.py
"""
import os
import django

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Ecomarket.settings')
django.setup()

from products.models import ProductCategory

def populate_product_categories():
    """Create default product categories"""
    
    categories = [
        {
            'name': 'Accessories',
            'slug': 'accessories',
            'description': 'Eco-friendly accessories including bags, jewelry, and personal items',
            'icon': 'fa-heart',
            'display_order': 1
        },
        {
            'name': 'Kitchen Items',
            'slug': 'kitchen_items',
            'description': 'Sustainable kitchen products and utensils',
            'icon': 'fa-utensils',
            'display_order': 2
        },
        {
            'name': 'Home & Living',
            'slug': 'home_living',
            'description': 'Eco-friendly home decor and living essentials',
            'icon': 'fa-couch',
            'display_order': 3
        },
        {
            'name': 'Craft & Tools',
            'slug': 'craft_tools',
            'description': 'Sustainable craft supplies and tools',
            'icon': 'fa-tools',
            'display_order': 4
        },
        {
            'name': 'Art Supplies',
            'slug': 'art_supplies',
            'description': 'Eco-friendly art materials and supplies',
            'icon': 'fa-palette',
            'display_order': 5
        }
    ]
    
    created_count = 0
    updated_count = 0
    
    for cat_data in categories:
        category, created = ProductCategory.objects.get_or_create(
            slug=cat_data['slug'],
            defaults=cat_data
        )
        
        if created:
            created_count += 1
            print(f"✓ Created: {category.name}")
        else:
            # Update existing category
            for key, value in cat_data.items():
                setattr(category, key, value)
            category.save()
            updated_count += 1
            print(f"↻ Updated: {category.name}")
    
    print(f"\n{'='*50}")
    print(f"Summary:")
    print(f"  Created: {created_count} categories")
    print(f"  Updated: {updated_count} categories")
    print(f"  Total: {ProductCategory.objects.count()} categories")
    print(f"{'='*50}")

if __name__ == '__main__':
    print("Populating Product Categories...")
    print(f"{'='*50}\n")
    populate_product_categories()
    print("\n✓ Done!")
