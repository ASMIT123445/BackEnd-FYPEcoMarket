from rest_framework import serializers
from .models import Cart, CartItem, Order, OrderItem
from products.serializers import ProductSerializer

class CartItemSerializer(serializers.ModelSerializer):
    product = ProductSerializer(read_only=True)
    product_id = serializers.IntegerField(write_only=True)
    total_price = serializers.ReadOnlyField()

    class Meta:
        model = CartItem
        fields = ['id', 'product', 'product_id', 'quantity', 'total_price', 'created_at']

class CartSerializer(serializers.ModelSerializer):
    items = CartItemSerializer(many=True, read_only=True)
    total_items = serializers.ReadOnlyField()
    total_price = serializers.ReadOnlyField()

    class Meta:
        model = Cart
        fields = ['id', 'items', 'total_items', 'total_price', 'created_at', 'updated_at']

class OrderItemSerializer(serializers.ModelSerializer):
    product = ProductSerializer(read_only=True)
    total_price = serializers.ReadOnlyField()

    class Meta:
        model = OrderItem
        fields = ['id', 'product', 'quantity', 'price', 'total_price']

class OrderSerializer(serializers.ModelSerializer):
    items = OrderItemSerializer(many=True, read_only=True)
    customer_name = serializers.SerializerMethodField()
    seller_subtotal = serializers.SerializerMethodField()

    class Meta:
        model = Order
        fields = [
            'id', 'customer_name', 'status', 'total_amount', 'seller_subtotal', 'items', 
            'payment_method', 'payment_status', 'transaction_id', 'esewa_ref_id',
            'shipping_address', 'phone_number',
            'created_at', 'updated_at'
        ]

    def get_customer_name(self, obj):
        user = obj.user
        if user.first_name and user.last_name:
            return f"{user.first_name} {user.last_name}"
        return user.username

    def get_seller_subtotal(self, obj):
        """
        Returns the subtotal for only the items belonging to the requesting seller.
        Falls back to total_amount if no seller context is available (e.g. admin views).
        """
        request = self.context.get('request')
        if request and hasattr(request, 'user') and request.user.is_authenticated and not request.user.is_staff:
            seller_items = obj.items.filter(product__seller=request.user)
            return float(sum(item.price * item.quantity for item in seller_items))
        # Admin or no context — return full order total
        return float(obj.total_amount)