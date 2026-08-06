from django.urls import path
from .views import (
    AdminStatsView, AdminUsersView, AdminSellersView,
    AdminProductsView, AdminOrdersView,
    AdminCustomersView, AdminRatingsView, AdminCategoriesView,
    AdminChartDataView,
)

urlpatterns = [
    path('stats/', AdminStatsView.as_view()),
    path('charts/', AdminChartDataView.as_view()),
    path('users/', AdminUsersView.as_view()),
    path('users/<int:user_id>/', AdminUsersView.as_view()),
    path('sellers/', AdminSellersView.as_view()),
    path('sellers/<int:seller_id>/', AdminSellersView.as_view()),
    path('products/', AdminProductsView.as_view()),
    path('products/<int:product_id>/', AdminProductsView.as_view()),
    path('orders/', AdminOrdersView.as_view()),
    path('orders/<int:order_id>/', AdminOrdersView.as_view()),
    path('customers/', AdminCustomersView.as_view()),
    path('customers/<int:customer_id>/', AdminCustomersView.as_view()),
    path('ratings/', AdminRatingsView.as_view()),
    path('ratings/<int:rating_id>/', AdminRatingsView.as_view()),
    path('categories/', AdminCategoriesView.as_view()),
    path('categories/<str:cat_type>/<int:cat_id>/', AdminCategoriesView.as_view()),
]
