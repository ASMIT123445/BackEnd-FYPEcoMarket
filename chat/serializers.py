from rest_framework import serializers
from .models import ChatRoom, Message


class MessageSerializer(serializers.ModelSerializer):
    sender_name = serializers.SerializerMethodField()

    class Meta:
        model = Message
        fields = ['id', 'sender', 'sender_name', 'content', 'created_at', 'is_read']
        read_only_fields = ['sender', 'created_at', 'is_read']

    def get_sender_name(self, obj):
        return obj.sender.username


class ChatRoomSerializer(serializers.ModelSerializer):
    messages = MessageSerializer(many=True, read_only=True)
    buyer_name = serializers.SerializerMethodField()
    seller_name = serializers.SerializerMethodField()

    class Meta:
        model = ChatRoom
        fields = ['id', 'order', 'buyer_name', 'seller_name', 'messages', 'created_at']

    def get_buyer_name(self, obj):
        return obj.buyer.username

    def get_seller_name(self, obj):
        return obj.seller.username
