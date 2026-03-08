#!/usr/bin/env python
"""
Script to apply verification system migrations
Run this from the Ecomarket directory: python apply_verification_migrations.py
"""
import os
import sys
import django

# Add the project directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Set up Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Ecomarket.settings')
django.setup()

from django.core.management import execute_from_command_line

def main():
    """Apply the verification system migrations"""
    print("🔄 Applying verification system migrations...")
    
    try:
        # Apply migrations
        print("\n📦 Applying products migrations...")
        execute_from_command_line(['manage.py', 'migrate', 'products'])
        
        print("\n👥 Applying users migrations...")
        execute_from_command_line(['manage.py', 'migrate', 'users'])
        
        print("\n✅ All migrations applied successfully!")
        print("\n🎉 Verification system is now ready!")
        print("\nNext steps:")
        print("1. Create a superuser: python manage.py createsuperuser")
        print("2. Start the server: python manage.py runserver")
        print("3. Access admin at: http://127.0.0.1:8000/admin/")
        print("4. Verify sellers and products from the admin interface")
        
    except Exception as e:
        print(f"❌ Error applying migrations: {e}")
        print("\nTry running manually:")
        print("python manage.py migrate products")
        print("python manage.py migrate users")

if __name__ == '__main__':
    main()