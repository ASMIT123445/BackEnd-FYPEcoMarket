from django.urls import path
from .views import GetOrCreateChatRoom, SendMessage, UnreadCount, OrderSellersView

urlpatterns = [
    path('chat/<int:order_id>/sellers/', OrderSellersView.as_view(), name='order-sellers'),
    path('chat/<int:order_id>/<int:seller_id>/', GetOrCreateChatRoom.as_view(), name='chat-room'),
    path('chat/<int:order_id>/<int:seller_id>/send/', SendMessage.as_view(), name='send-message'),
    path('chat/unread/', UnreadCount.as_view(), name='unread-count'),
]
