from django.urls import path
from . import views

urlpatterns = [
    path('cart/', views.get_cart, name='get_cart'),
    path('cart/add/', views.add_to_cart, name='add_to_cart'),
    path('cart/items/<int:item_id>/', views.update_cart_item, name='update_cart_item'),
    path('cart/items/<int:item_id>/remove/', views.remove_from_cart, name='remove_from_cart'),
    path('cart/clear/', views.clear_cart, name='clear_cart'),
    path('cart/count/', views.get_cart_count, name='get_cart_count'),
    path('orders/history/', views.get_order_history, name='get_order_history'),
    path('orders/create/', views.create_order, name='create_order'),
    
    # eSewa Payment endpoints
    path('orders/esewa/initiate/', views.initiate_esewa_payment, name='initiate_esewa_payment'),
    path('orders/esewa/verify/', views.esewa_payment_verify, name='esewa_payment_verify'),
    path('orders/esewa/failure/', views.esewa_payment_failure, name='esewa_payment_failure'),
    path('orders/cod/create/', views.create_cod_order, name='create_cod_order'),
]