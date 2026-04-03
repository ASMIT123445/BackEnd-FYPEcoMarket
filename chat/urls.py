from django.urls import path
from .views import GetOrCreateChatRoom, SendMessage, UnreadCount

urlpatterns = [
    path('chat/<int:order_id>/', GetOrCreateChatRoom.as_view(), name='chat-room'),
    path('chat/<int:order_id>/send/', SendMessage.as_view(), name='send-message'),
    path('chat/unread/', UnreadCount.as_view(), name='unread-count'),
]
