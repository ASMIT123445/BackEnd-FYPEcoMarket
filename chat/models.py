from django.db import models
from django.contrib.auth.models import User
from orders.models import Order


class ChatRoom(models.Model):
    """One chat room per order per seller — supports multi-seller orders"""
    order = models.ForeignKey(Order, on_delete=models.CASCADE, related_name='chat_rooms')
    buyer = models.ForeignKey(User, on_delete=models.CASCADE, related_name='buyer_chats')
    seller = models.ForeignKey(User, on_delete=models.CASCADE, related_name='seller_chats')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('order', 'seller')  # one room per seller per order

    def __str__(self):
        return f"Chat Order#{self.order.id} — {self.buyer.username} ↔ {self.seller.username}"


class Message(models.Model):
    room = models.ForeignKey(ChatRoom, on_delete=models.CASCADE, related_name='messages')
    sender = models.ForeignKey(User, on_delete=models.CASCADE)
    content = models.TextField(blank=True)
    image = models.ImageField(upload_to='chat_images/', blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    is_read = models.BooleanField(default=False)

    class Meta:
        ordering = ['created_at']

    def __str__(self):
        return f"{self.sender.username}: {self.content[:40]}"
