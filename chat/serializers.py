from rest_framework import serializers
from .models import ChatRoom, Message


class MessageSerializer(serializers.ModelSerializer):
    sender_name = serializers.SerializerMethodField()
    image_url = serializers.SerializerMethodField()

    class Meta:
        model = Message
        fields = ['id', 'sender', 'sender_name', 'content', 'image_url', 'created_at', 'is_read']
        read_only_fields = ['sender', 'created_at', 'is_read']

    def get_sender_name(self, obj):
        return obj.sender.username

    def get_image_url(self, obj):
        request = self.context.get('request')
        if obj.image and request:
            return request.build_absolute_uri(obj.image.url)
        return None


class ChatRoomSerializer(serializers.ModelSerializer):
    messages = serializers.SerializerMethodField()
    buyer_name = serializers.SerializerMethodField()
    seller_name = serializers.SerializerMethodField()
    seller_id = serializers.SerializerMethodField()

    class Meta:
        model = ChatRoom
        fields = ['id', 'order', 'buyer_name', 'seller_id', 'seller_name', 'messages', 'created_at']

    def get_messages(self, obj):
        request = self.context.get('request')
        return MessageSerializer(obj.messages.all(), many=True, context={'request': request}).data

    def get_buyer_name(self, obj):
        return obj.buyer.username

    def get_seller_name(self, obj):
        return obj.seller.username

    def get_seller_id(self, obj):
        return obj.seller.id
