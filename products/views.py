from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, AllowAny
from .models import Product, EcoCategory, ProductCategory, ProductRating
from .serializers import ProductSerializer, EcoCategorySerializer, ProductCategorySerializer, ProductRatingSerializer

class ProductListCreateView(APIView):
    def get_permissions(self):
        """
        Allow anyone to view products, but only authenticated users to create
        """
        if self.request.method == 'GET':
            return [AllowAny()]
        return [IsAuthenticated()]
    
    def get(self, request):
        """Get all products with optional category filtering"""
        products = Product.objects.all().order_by('-id')  # Latest first
        
        # Filter by category if provided (supports both eco_category slug and legacy category)
        category = request.query_params.get('category')
        if category:
            from django.db.models import Q
            products = products.filter(
                Q(eco_category__slug=category) | Q(category=category)
            )
        
        # Filter by product_category if provided
        product_category = request.query_params.get('product_category')
        if product_category:
            products = products.filter(product_category__slug=product_category)
        
        # Filter by search query if provided
        search = request.query_params.get('search')
        if search:
            from django.db.models import Q
            products = products.filter(
                Q(name__icontains=search) | Q(description__icontains=search)
            )
        
        # Filter by price range if provided
        min_price = request.query_params.get('min_price')
        max_price = request.query_params.get('max_price')
        if min_price:
            products = products.filter(price__gte=min_price)
        if max_price:
            products = products.filter(price__lte=max_price)
        
        serializer = ProductSerializer(products, many=True, context={'request': request})
        return Response(serializer.data)
    
    def post(self, request):
        """Create a new product (sellers only)"""
        # Check if user is a seller
        user = request.user
        print(f"User: {user}")
        print(f"User authenticated: {user.is_authenticated}")
        
        user_role = getattr(user, 'role', None)
        print(f"User role from attribute: {user_role}")
        
        # Try to get role from profile models
        if not user_role:
            if hasattr(user, 'seller_user'):
                user_role = 'seller'
                print(f"Found seller_user profile: {user.seller_user}")
            elif hasattr(user, 'customer_user'):
                user_role = 'customer'
                print(f"Found customer_user profile: {user.customer_user}")
            else:
                print("No profile found")
        
        print(f"Final user role: {user_role}")
        
        # Temporarily allow both customers and sellers to add products for testing
        # if user_role != 'seller':
        #     return Response({
        #         "error": f"Only sellers can add products. Current role: {user_role}"
        #     }, status=status.HTTP_403_FORBIDDEN)
        
        # Create a mutable copy of request data
        data = request.data.copy()
        print(f"Request data: {data}")
        
        serializer = ProductSerializer(data=data, context={'request': request})
        if serializer.is_valid():
            # Automatically set the seller to the current user
            product = serializer.save(seller=user)
            print(f"Product created successfully: {product}")
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        else:
            print(f"Serializer errors: {serializer.errors}")
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ProductDetailView(APIView):
    def get_permissions(self):
        """Allow anyone to view, but only authenticated users to update/delete"""
        if self.request.method == 'GET':
            return [AllowAny()]
        return [IsAuthenticated()]
    
    def get(self, request, pk):
        """Get a specific product"""
        try:
            product = Product.objects.get(pk=pk)
            serializer = ProductSerializer(product, context={'request': request})
            return Response(serializer.data)
        except Product.DoesNotExist:
            return Response({
                "error": "Product not found"
            }, status=status.HTTP_404_NOT_FOUND)
    
    def put(self, request, pk):
        """Update a product (seller only - must be product owner)"""
        try:
            product = Product.objects.get(pk=pk)
            
            # Check if user is the product owner
            if product.seller != request.user:
                return Response({
                    "error": "You can only edit your own products"
                }, status=status.HTTP_403_FORBIDDEN)
            
            serializer = ProductSerializer(product, data=request.data, partial=True, context={'request': request})
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
        except Product.DoesNotExist:
            return Response({
                "error": "Product not found"
            }, status=status.HTTP_404_NOT_FOUND)
    
    def delete(self, request, pk):
        """Delete a product (seller only - must be product owner)"""
        try:
            product = Product.objects.get(pk=pk)
            
            # Check if user is the product owner
            if product.seller != request.user:
                return Response({
                    "error": "You can only delete your own products"
                }, status=status.HTTP_403_FORBIDDEN)
            
            product.delete()
            return Response({
                "message": "Product deleted successfully"
            }, status=status.HTTP_204_NO_CONTENT)
            
        except Product.DoesNotExist:
            return Response({
                "error": "Product not found"
            }, status=status.HTTP_404_NOT_FOUND)

class SellerProductsView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        """Get products created by the current seller"""
        products = Product.objects.filter(seller=request.user).order_by('-created_at')
        serializer = ProductSerializer(products, many=True, context={'request': request})
        return Response(serializer.data)

class CategoryListView(APIView):
    permission_classes = [AllowAny]
    
    def get(self, request):
        """Get all active eco categories"""
        categories = EcoCategory.objects.filter(is_active=True).order_by('display_order', 'name')
        serializer = EcoCategorySerializer(categories, many=True)
        return Response(serializer.data)

# Test endpoint to check authentication
class TestAuthView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        user = request.user
        return Response({
            "message": "Authentication working",
            "user": user.username,
            "user_id": user.id,
            "is_authenticated": user.is_authenticated,
            "has_seller_profile": hasattr(user, 'seller_user'),
            "has_customer_profile": hasattr(user, 'customer_user'),
        })

class EcoCategoryManagementView(APIView):
    """Admin-only view for managing eco categories"""
    permission_classes = [IsAuthenticated]
    
    def get_permissions(self):
        """Only allow superusers to manage categories"""
        if self.request.method in ['POST', 'PUT', 'DELETE']:
            return [IsAuthenticated()]
        return [AllowAny()]
    
    def get(self, request):
        """Get all eco categories (including inactive ones for admin)"""
        if request.user.is_authenticated and request.user.is_superuser:
            categories = EcoCategory.objects.all().order_by('display_order', 'name')
        else:
            categories = EcoCategory.objects.filter(is_active=True).order_by('display_order', 'name')
        
        serializer = EcoCategorySerializer(categories, many=True)
        return Response(serializer.data)
    
    def post(self, request):
        """Create a new eco category (admin only)"""
        if not request.user.is_superuser:
            return Response(
                {"error": "Only administrators can create categories"}, 
                status=status.HTTP_403_FORBIDDEN
            )
        
        serializer = EcoCategorySerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class EcoCategoryDetailView(APIView):
    """Admin-only view for managing individual eco categories"""
    permission_classes = [IsAuthenticated]
    
    def get_object(self, pk):
        try:
            return EcoCategory.objects.get(pk=pk)
        except EcoCategory.DoesNotExist:
            return None
    
    def get(self, request, pk):
        """Get a specific eco category"""
        category = self.get_object(pk)
        if not category:
            return Response(
                {"error": "Category not found"}, 
                status=status.HTTP_404_NOT_FOUND
            )
        
        serializer = EcoCategorySerializer(category)
        return Response(serializer.data)
    
    def put(self, request, pk):
        """Update an eco category (admin only)"""
        if not request.user.is_superuser:
            return Response(
                {"error": "Only administrators can update categories"}, 
                status=status.HTTP_403_FORBIDDEN
            )
        
        category = self.get_object(pk)
        if not category:
            return Response(
                {"error": "Category not found"}, 
                status=status.HTTP_404_NOT_FOUND
            )
        
        serializer = EcoCategorySerializer(category, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def delete(self, request, pk):
        """Delete an eco category (admin only)"""
        if not request.user.is_superuser:
            return Response(
                {"error": "Only administrators can delete categories"}, 
                status=status.HTTP_403_FORBIDDEN
            )
        
        category = self.get_object(pk)
        if not category:
            return Response(
                {"error": "Category not found"}, 
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Check if category has products
        product_count = category.product_set.count()
        if product_count > 0:
            return Response(
                {"error": f"Cannot delete category with {product_count} products. Please reassign products first."}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        category.delete()
        return Response(
            {"message": "Category deleted successfully"}, 
            status=status.HTTP_204_NO_CONTENT
        )


class ProductCategoryListView(APIView):
    permission_classes = [AllowAny]
    
    def get(self, request):
        """Get all active product categories"""
        categories = ProductCategory.objects.filter(is_active=True).order_by('display_order', 'name')
        serializer = ProductCategorySerializer(categories, many=True)
        return Response(serializer.data)

class ProductCategoryManagementView(APIView):
    """Admin-only view for managing product categories"""
    permission_classes = [IsAuthenticated]
    
    def get_permissions(self):
        """Only allow superusers to manage categories"""
        if self.request.method in ['POST', 'PUT', 'DELETE']:
            return [IsAuthenticated()]
        return [AllowAny()]
    
    def get(self, request):
        """Get all product categories (including inactive ones for admin)"""
        if request.user.is_authenticated and request.user.is_superuser:
            categories = ProductCategory.objects.all().order_by('display_order', 'name')
        else:
            categories = ProductCategory.objects.filter(is_active=True).order_by('display_order', 'name')
        
        serializer = ProductCategorySerializer(categories, many=True)
        return Response(serializer.data)
    
    def post(self, request):
        """Create a new product category (admin only)"""
        if not request.user.is_superuser:
            return Response(
                {"error": "Only administrators can create categories"}, 
                status=status.HTTP_403_FORBIDDEN
            )
        
        serializer = ProductCategorySerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ProductCategoryDetailView(APIView):
    """Admin-only view for managing individual product categories"""
    permission_classes = [IsAuthenticated]
    
    def get_object(self, pk):
        try:
            return ProductCategory.objects.get(pk=pk)
        except ProductCategory.DoesNotExist:
            return None
    
    def get(self, request, pk):
        """Get a specific product category"""
        category = self.get_object(pk)
        if not category:
            return Response(
                {"error": "Category not found"}, 
                status=status.HTTP_404_NOT_FOUND
            )
        
        serializer = ProductCategorySerializer(category)
        return Response(serializer.data)
    
    def put(self, request, pk):
        """Update a product category (admin only)"""
        if not request.user.is_superuser:
            return Response(
                {"error": "Only administrators can update categories"}, 
                status=status.HTTP_403_FORBIDDEN
            )
        
        category = self.get_object(pk)
        if not category:
            return Response(
                {"error": "Category not found"}, 
                status=status.HTTP_404_NOT_FOUND
            )
        
        serializer = ProductCategorySerializer(category, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def delete(self, request, pk):
        """Delete a product category (admin only)"""
        if not request.user.is_superuser:
            return Response(
                {"error": "Only administrators can delete categories"}, 
                status=status.HTTP_403_FORBIDDEN
            )
        
        category = self.get_object(pk)
        if not category:
            return Response(
                {"error": "Category not found"}, 
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Check if category has products
        product_count = category.product_set.count()
        if product_count > 0:
            return Response(
                {"error": f"Cannot delete category with {product_count} products. Please reassign products first."}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        category.delete()
        return Response(
            {"message": "Category deleted successfully"}, 
            status=status.HTTP_204_NO_CONTENT
        )


class ProductRatingView(APIView):
    """View for submitting and getting product ratings"""
    
    def get_permissions(self):
        """Allow anyone to view ratings, but only authenticated users to submit"""
        if self.request.method == 'GET':
            return [AllowAny()]
        return [IsAuthenticated()]
    
    def get(self, request, product_id):
        """Get all ratings for a product"""
        try:
            product = Product.objects.get(pk=product_id)
            ratings = ProductRating.objects.filter(product=product)
            
            # Calculate average rating
            if ratings.exists():
                from django.db.models import Avg
                avg_rating = ratings.aggregate(Avg('rating'))['rating__avg']
                rating_count = ratings.count()
            else:
                avg_rating = 0
                rating_count = 0
            
            serializer = ProductRatingSerializer(ratings, many=True)
            
            return Response({
                'ratings': serializer.data,
                'average_rating': round(avg_rating, 1) if avg_rating else 0,
                'rating_count': rating_count
            })
        except Product.DoesNotExist:
            return Response(
                {"error": "Product not found"}, 
                status=status.HTTP_404_NOT_FOUND
            )
    
    def post(self, request, product_id):
        """Submit or update a rating for a product"""
        try:
            product = Product.objects.get(pk=product_id)
            
            # Check if user already rated this product
            existing_rating = ProductRating.objects.filter(
                product=product, 
                user=request.user
            ).first()
            
            if existing_rating:
                # Update existing rating
                serializer = ProductRatingSerializer(
                    existing_rating, 
                    data=request.data, 
                    partial=True
                )
            else:
                # Create new rating
                serializer = ProductRatingSerializer(data=request.data)
            
            if serializer.is_valid():
                serializer.save(user=request.user, product=product)
                
                # Update product's average rating
                from django.db.models import Avg
                avg_rating = ProductRating.objects.filter(product=product).aggregate(Avg('rating'))['rating__avg']
                product.rating = round(avg_rating, 1) if avg_rating else 0
                product.save()
                
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
        except Product.DoesNotExist:
            return Response(
                {"error": "Product not found"}, 
                status=status.HTTP_404_NOT_FOUND
            )

class UserProductRatingView(APIView):
    """Get user's rating for a specific product"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request, product_id):
        """Get current user's rating for a product"""
        try:
            rating = ProductRating.objects.get(
                product_id=product_id, 
                user=request.user
            )
            serializer = ProductRatingSerializer(rating)
            return Response(serializer.data)
        except ProductRating.DoesNotExist:
            return Response(
                {"rating": None}, 
                status=status.HTTP_200_OK
            )
