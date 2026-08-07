from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.models import User
from orders.models import Order
from .models import ChatRoom, Message
from .serializers import ChatRoomSerializer, MessageSerializer


def get_order_seller_ids(order):
    return list(set(order.items.values_list('product__seller_id', flat=True)))


class OrderSellersView(APIView):
    """List all unique sellers in an order so buyer can pick who to chat with"""
    permission_classes = [IsAuthenticated]

    def get(self, request, order_id):
        try:
            order = Order.objects.get(id=order_id)
        except Order.DoesNotExist:
            return Response({'error': 'Order not found'}, status=status.HTTP_404_NOT_FOUND)

        seller_ids = get_order_seller_ids(order)
        # Allow buyer or any seller in the order
        if request.user != order.user and request.user.id not in seller_ids:
            return Response({'error': 'Not authorized'}, status=status.HTTP_403_FORBIDDEN)

        sellers = User.objects.filter(id__in=seller_ids)
        data = [{'id': s.id, 'username': s.username} for s in sellers]
        return Response(data)


class GetOrCreateChatRoom(APIView):
    """Get or create a chat room for a specific order + seller pair"""
    permission_classes = [IsAuthenticated]

    def get(self, request, order_id, seller_id):
        try:
            order = Order.objects.get(id=order_id)
        except Order.DoesNotExist:
            return Response({'error': 'Order not found'}, status=status.HTTP_404_NOT_FOUND)

        seller_ids = get_order_seller_ids(order)
        # Allow buyer or the specific seller
        if request.user != order.user and request.user.id not in seller_ids:
            return Response({'error': 'Not authorized'}, status=status.HTTP_403_FORBIDDEN)

        try:
            seller = User.objects.get(id=seller_id)
        except User.DoesNotExist:
            return Response({'error': 'Seller not found'}, status=status.HTTP_404_NOT_FOUND)

        if seller.id not in seller_ids:
            return Response({'error': 'This seller is not part of this order'}, status=status.HTTP_400_BAD_REQUEST)

        room, _ = ChatRoom.objects.get_or_create(
            order=order,
            seller=seller,
            defaults={'buyer': order.user}
        )

        # Mark messages as read for current user
        room.messages.exclude(sender=request.user).update(is_read=True)

        serializer = ChatRoomSerializer(room, context={'request': request})
        return Response(serializer.data)


class SendMessage(APIView):
    """Send a message in a specific order+seller chat room"""
    permission_classes = [IsAuthenticated]

    def post(self, request, order_id, seller_id):
        try:
            order = Order.objects.get(id=order_id)
        except Order.DoesNotExist:
            return Response({'error': 'Order not found'}, status=status.HTTP_404_NOT_FOUND)

        seller_ids = get_order_seller_ids(order)
        if request.user != order.user and request.user.id not in seller_ids:
            return Response({'error': 'Not authorized'}, status=status.HTTP_403_FORBIDDEN)

        content = request.data.get('content', '').strip()
        image = request.FILES.get('image')

        if not content and not image:
            return Response({'error': 'Message must have text or an image'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            room = ChatRoom.objects.get(order=order, seller_id=seller_id)
        except ChatRoom.DoesNotExist:
            try:
                seller = User.objects.get(id=seller_id)
            except User.DoesNotExist:
                return Response({'error': 'Seller not found'}, status=status.HTTP_404_NOT_FOUND)
            room, _ = ChatRoom.objects.get_or_create(
                order=order,
                seller=seller,
                defaults={'buyer': order.user}
            )

        message = Message.objects.create(
            room=room,
            sender=request.user,
            content=content,
            image=image if image else None
        )
        serializer = MessageSerializer(message, context={'request': request})
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class UnreadCount(APIView):
    """Get unread message count for current user"""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        count = Message.objects.filter(
            room__in=ChatRoom.objects.filter(buyer=request.user) | ChatRoom.objects.filter(seller=request.user),
            is_read=False
        ).exclude(sender=request.user).count()
        return Response({'unread_count': count})
