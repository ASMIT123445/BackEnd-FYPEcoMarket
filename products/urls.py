from django.urls import path
from .views import (
    ProductListCreateView, ProductDetailView, TestAuthView, CategoryListView, 
    SellerProductsView, EcoCategoryManagementView, EcoCategoryDetailView,
    ProductCategoryListView, ProductCategoryManagementView, ProductCategoryDetailView,
    ProductRatingView, UserProductRatingView, CanReviewProductView, SearchSuggestionsView
)

urlpatterns = [
    path('', ProductListCreateView.as_view(), name='product-list-create'),
    path('<int:pk>/', ProductDetailView.as_view(), name='product-detail'),
    path('categories/', CategoryListView.as_view(), name='category-list'),
    path('suggestions/', SearchSuggestionsView.as_view(), name='search-suggestions'),
    path('eco-categories/', EcoCategoryManagementView.as_view(), name='eco-category-management'),
    path('eco-categories/<int:pk>/', EcoCategoryDetailView.as_view(), name='eco-category-detail'),
    path('product-categories/', ProductCategoryListView.as_view(), name='product-category-list'),
    path('product-categories/manage/', ProductCategoryManagementView.as_view(), name='product-category-management'),
    path('product-categories/<int:pk>/', ProductCategoryDetailView.as_view(), name='product-category-detail'),
    path('<int:product_id>/ratings/', ProductRatingView.as_view(), name='product-ratings'),
    path('<int:product_id>/my-rating/', UserProductRatingView.as_view(), name='user-product-rating'),
    path('<int:product_id>/can-review/', CanReviewProductView.as_view(), name='can-review-product'),
    path('seller/my-products/', SellerProductsView.as_view(), name='seller-products'),
    path('test-auth/', TestAuthView.as_view(), name='test-auth'),
]