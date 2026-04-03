from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.models import User
from orders.models import Order
from .models import ChatRoom, Message
from .serializers import ChatRoomSerializer, MessageSerializer


class GetOrCreateChatRoom(APIView):
    """Get or create a chat room for an order"""
    permission_classes = [IsAuthenticated]

    def get(self, request, order_id):
        try:
            order = Order.objects.get(id=order_id)
        except Order.DoesNotExist:
            return Response({'error': 'Order not found'}, status=status.HTTP_404_NOT_FOUND)

        # Only buyer or seller of this order can access
        seller_ids = list(order.items.values_list('product__seller_id', flat=True))
        if request.user != order.user and request.user.id not in seller_ids:
            return Response({'error': 'Not authorized'}, status=status.HTTP_403_FORBIDDEN)

        # Get seller (first seller in the order)
        seller_id = seller_ids[0] if seller_ids else None
        if not seller_id:
            return Response({'error': 'No seller found for this order'}, status=status.HTTP_400_BAD_REQUEST)

        seller = User.objects.get(id=seller_id)
        room, _ = ChatRoom.objects.get_or_create(
            order=order,
            defaults={'buyer': order.user, 'seller': seller}
        )

        # Mark messages as read for current user
        room.messages.exclude(sender=request.user).update(is_read=True)

        serializer = ChatRoomSerializer(room)
        return Response(serializer.data)


class SendMessage(APIView):
    """Send a message in a chat room"""
    permission_classes = [IsAuthenticated]

    def post(self, request, order_id):
        try:
            order = Order.objects.get(id=order_id)
        except Order.DoesNotExist:
            return Response({'error': 'Order not found'}, status=status.HTTP_404_NOT_FOUND)

        seller_ids = list(order.items.values_list('product__seller_id', flat=True))
        if request.user != order.user and request.user.id not in seller_ids:
            return Response({'error': 'Not authorized'}, status=status.HTTP_403_FORBIDDEN)

        content = request.data.get('content', '').strip()
        if not content:
            return Response({'error': 'Message cannot be empty'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            room = ChatRoom.objects.get(order=order)
        except ChatRoom.DoesNotExist:
            return Response({'error': 'Chat room not found. Open the chat first.'}, status=status.HTTP_404_NOT_FOUND)

        message = Message.objects.create(room=room, sender=request.user, content=content)
        serializer = MessageSerializer(message)
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class UnreadCount(APIView):
    """Get unread message count for a user across all chats"""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        count = Message.objects.filter(
            room__in=ChatRoom.objects.filter(
                buyer=request.user
            ) | ChatRoom.objects.filter(seller=request.user),
            is_read=False
        ).exclude(sender=request.user).count()
        return Response({'unread_count': count})
