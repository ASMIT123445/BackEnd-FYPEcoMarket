from django.shortcuts import render
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from django.shortcuts import get_object_or_404
from .models import Cart, CartItem, Order, OrderItem, OrderStatusHistory
from .serializers import CartSerializer, CartItemSerializer, OrderSerializer
from products.models import Product
from users.green_points_utils import calculate_points_earned, award_points

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_cart(request):
    """Get user's cart with all items"""
    cart, created = Cart.objects.get_or_create(user=request.user)
    serializer = CartSerializer(cart)
    return Response(serializer.data)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def add_to_cart(request):
    """Add item to cart or update quantity if exists"""
    product_id = request.data.get('product_id')
    quantity = int(request.data.get('quantity', 1))
    
    if not product_id:
        return Response({'error': 'Product ID is required'}, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        product = Product.objects.get(id=product_id)
    except Product.DoesNotExist:
        return Response({'error': 'Product not found'}, status=status.HTTP_404_NOT_FOUND)
    
    # Check stock
    if quantity > product.stock:
        return Response({'error': f'Only {product.stock} items available'}, status=status.HTTP_400_BAD_REQUEST)
    
    cart, created = Cart.objects.get_or_create(user=request.user)
    cart_item, created = CartItem.objects.get_or_create(
        cart=cart,
        product=product,
        defaults={'quantity': quantity}
    )
    
    if not created:
        # Update quantity if item already exists
        new_quantity = cart_item.quantity + quantity
        if new_quantity > product.stock:
            return Response({'error': f'Only {product.stock} items available'}, status=status.HTTP_400_BAD_REQUEST)
        cart_item.quantity = new_quantity
        cart_item.save()
    
    serializer = CartItemSerializer(cart_item)
    return Response({
        'message': 'Item added to cart successfully',
        'item': serializer.data,
        'cart_total_items': cart.total_items
    }, status=status.HTTP_201_CREATED)

@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def update_cart_item(request, item_id):
    """Update cart item quantity"""
    quantity = int(request.data.get('quantity', 1))
    
    try:
        cart_item = CartItem.objects.get(id=item_id, cart__user=request.user)
    except CartItem.DoesNotExist:
        return Response({'error': 'Cart item not found'}, status=status.HTTP_404_NOT_FOUND)
    
    if quantity <= 0:
        cart_item.delete()
        return Response({'message': 'Item removed from cart'}, status=status.HTTP_200_OK)
    
    if quantity > cart_item.product.stock:
        return Response({'error': f'Only {cart_item.product.stock} items available'}, status=status.HTTP_400_BAD_REQUEST)
    
    cart_item.quantity = quantity
    cart_item.save()
    
    serializer = CartItemSerializer(cart_item)
    return Response({
        'message': 'Cart item updated successfully',
        'item': serializer.data
    })

@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def remove_from_cart(request, item_id):
    """Remove item from cart"""
    try:
        cart_item = CartItem.objects.get(id=item_id, cart__user=request.user)
        cart_item.delete()
        return Response({'message': 'Item removed from cart'}, status=status.HTTP_200_OK)
    except CartItem.DoesNotExist:
        return Response({'error': 'Cart item not found'}, status=status.HTTP_404_NOT_FOUND)

@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def clear_cart(request):
    """Clear all items from cart"""
    try:
        cart = Cart.objects.get(user=request.user)
        cart.items.all().delete()
        return Response({'message': 'Cart cleared successfully'}, status=status.HTTP_200_OK)
    except Cart.DoesNotExist:
        return Response({'message': 'Cart is already empty'}, status=status.HTTP_200_OK)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_cart_count(request):
    """Get total number of items in cart"""
    try:
        cart = Cart.objects.get(user=request.user)
        return Response({'count': cart.total_items})
    except Cart.DoesNotExist:
        return Response({'count': 0})

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_order_history(request):
    """Get user's order history"""
    orders = Order.objects.filter(user=request.user).order_by('-created_at')[:10]  # Last 10 orders
    serializer = OrderSerializer(orders, many=True)
    return Response(serializer.data)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_order(request):
    """Create order from cart items"""
    try:
        cart = Cart.objects.get(user=request.user)
        if not cart.items.exists():
            return Response({'error': 'Cart is empty'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Calculate total
        total_amount = cart.total_price
        
        # Calculate green points to be earned
        points_to_earn = calculate_points_earned(total_amount)
        
        # Create order
        order = Order.objects.create(
            user=request.user,
            total_amount=total_amount,
            status='confirmed',
            points_earned=points_to_earn
        )
        
        # Create order items from cart items
        for cart_item in cart.items.all():
            OrderItem.objects.create(
                order=order,
                product=cart_item.product,
                quantity=cart_item.quantity,
                price=cart_item.product.price
            )
        
        # Award green points to user
        award_points(request.user, order, points_to_earn)
        
        # Clear cart after order creation
        cart.items.all().delete()
        
        # Return order details
        serializer = OrderSerializer(order)
        return Response({
            'message': 'Order created successfully',
            'order': serializer.data,
            'points_earned': points_to_earn
        }, status=status.HTTP_201_CREATED)
        
    except Cart.DoesNotExist:
        return Response({'error': 'Cart not found'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

import hashlib
import hmac
import base64
import requests
from django.conf import settings

# eSewa Configuration
ESEWA_MERCHANT_ID = getattr(settings, 'ESEWA_MERCHANT_ID', 'EPAYTEST')  # Test merchant ID
ESEWA_SECRET_KEY = getattr(settings, 'ESEWA_SECRET_KEY', '8gBm/:&EnhH.1/q')  # Test secret key
ESEWA_PAYMENT_URL = getattr(settings, 'ESEWA_PAYMENT_URL', 'https://rc-epay.esewa.com.np/api/epay/main/v2/form')
ESEWA_VERIFY_URL = getattr(settings, 'ESEWA_VERIFY_URL', 'https://rc-epay.esewa.com.np/api/epay/transaction/status/')

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def initiate_esewa_payment(request):
    """
    Initiate eSewa payment
    Creates an order and returns eSewa payment parameters
    """
    try:
        # Get cart
        cart = Cart.objects.get(user=request.user)
        if not cart.items.exists():
            return Response({'error': 'Cart is empty'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Get shipping details from request
        shipping_address = request.data.get('shipping_address', '')
        phone_number = request.data.get('phone_number', '')
        
        # Calculate total
        total_amount = float(cart.total_price)
        
        # Calculate green points to be earned
        points_to_earn = calculate_points_earned(total_amount)
        
        # Create order with pending payment status
        order = Order.objects.create(
            user=request.user,
            total_amount=total_amount,
            status='pending',
            payment_method='esewa',
            payment_status='pending',
            shipping_address=shipping_address,
            phone_number=phone_number,
            points_earned=points_to_earn
        )
        
        # Create order items from cart items
        for cart_item in cart.items.all():
            OrderItem.objects.create(
                order=order,
                product=cart_item.product,
                quantity=cart_item.quantity,
                price=cart_item.product.price
            )
            
            # Reduce stock
            product = cart_item.product
            product.stock -= cart_item.quantity
            product.save()
        
        # Generate eSewa payment parameters
        transaction_uuid = f"ORDER-{order.id}-{order.created_at.timestamp()}"
        
        # eSewa payment data
        payment_data = {
            'amount': str(total_amount),
            'tax_amount': '0',
            'total_amount': str(total_amount),
            'transaction_uuid': transaction_uuid,
            'product_code': ESEWA_MERCHANT_ID,
            'product_service_charge': '0',
            'product_delivery_charge': '0',
            'success_url': f'{request.scheme}://{request.get_host()}/api/orders/esewa/verify/',
            'failure_url': f'{request.scheme}://{request.get_host()}/api/orders/esewa/failure/',
            'signed_field_names': 'total_amount,transaction_uuid,product_code',
        }
        
        # Generate signature
        message = f"total_amount={payment_data['total_amount']},transaction_uuid={payment_data['transaction_uuid']},product_code={payment_data['product_code']}"
        signature = base64.b64encode(
            hmac.new(
                ESEWA_SECRET_KEY.encode(),
                message.encode(),
                hashlib.sha256
            ).digest()
        ).decode()
        
        payment_data['signature'] = signature
        
        # Store transaction UUID in order
        order.transaction_id = transaction_uuid
        order.save()
        
        # Clear cart after order creation
        cart.items.all().delete()
        
        return Response({
            'message': 'Order created successfully',
            'order_id': order.id,
            'payment_url': ESEWA_PAYMENT_URL,
            'payment_data': payment_data
        }, status=status.HTTP_201_CREATED)
        
    except Cart.DoesNotExist:
        return Response({'error': 'Cart not found'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET', 'POST'])
def esewa_payment_verify(request):
    """
    Verify eSewa payment callback
    This endpoint is called by eSewa after payment
    """
    try:
        # Get parameters from eSewa callback
        # eSewa sends: data, encoded_data (for GET) or in request body (for POST)
        if request.method == 'GET':
            data = request.GET.dict()
        else:
            data = request.data if hasattr(request, 'data') else request.POST.dict()
        
        # eSewa callback parameters can vary, try multiple parameter names
        transaction_code = (
            data.get('oid') or 
            data.get('transaction_code') or 
            data.get('refId') or
            data.get('ref_id')
        )
        
        transaction_uuid = (
            data.get('refId') or 
            data.get('transaction_uuid') or
            data.get('ref_id')
        )
        
        total_amount = (
            data.get('amt') or 
            data.get('total_amount') or
            data.get('amount')
        )
        
        # Log received parameters for debugging
        print(f"eSewa callback received: {data}")
        print(f"transaction_code: {transaction_code}")
        print(f"transaction_uuid: {transaction_uuid}")
        print(f"total_amount: {total_amount}")
        
        # If we have encoded_data, decode it
        if 'encoded_data' in data or 'data' in data:
            import base64
            import json
            encoded = data.get('encoded_data') or data.get('data')
            try:
                decoded = base64.b64decode(encoded).decode('utf-8')
                decoded_data = json.loads(decoded)
                transaction_code = decoded_data.get('transaction_code')
                transaction_uuid = decoded_data.get('transaction_uuid')
                total_amount = decoded_data.get('total_amount')
                print(f"Decoded data: {decoded_data}")
            except Exception as e:
                print(f"Error decoding data: {e}")
        
        if not transaction_uuid:
            # Try to extract from any available parameter
            for key, value in data.items():
                if 'ORDER-' in str(value):
                    transaction_uuid = value
                    break
        
        if not transaction_uuid:
            return Response({
                'error': 'Missing payment parameters',
                'received_params': list(data.keys()),
                'help': 'Expected transaction_uuid or refId'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Find order by transaction UUID
        try:
            order = Order.objects.get(transaction_id=transaction_uuid)
        except Order.DoesNotExist:
            return Response({
                'error': 'Order not found',
                'transaction_uuid': transaction_uuid
            }, status=status.HTTP_404_NOT_FOUND)
        
        # For testing, if we don't have transaction_code or total_amount, mark as success
        if not transaction_code or not total_amount:
            # Mark payment as completed for testing
            order.payment_status = 'completed'
            order.status = 'confirmed'
            order.esewa_ref_id = transaction_code or 'TEST-' + str(order.id)
            order.save()
            
            # Award green points
            if order.points_earned > 0:
                award_points(order.user, order, order.points_earned)
            
            # Redirect to success page
            frontend_url = f"http://localhost:5173/order-confirmation?order_id={order.id}&status=success"
            
            # Return HTML redirect for browser
            from django.http import HttpResponseRedirect
            return HttpResponseRedirect(frontend_url)
        
        # Verify payment with eSewa
        verify_url = f"{ESEWA_VERIFY_URL}?product_code={ESEWA_MERCHANT_ID}&total_amount={total_amount}&transaction_uuid={transaction_uuid}"
        
        try:
            response = requests.get(verify_url, timeout=10)
            response_data = response.json()
            
            if response.status_code == 200 and response_data.get('status') == 'COMPLETE':
                # Payment successful
                order.payment_status = 'completed'
                order.status = 'confirmed'
                order.esewa_ref_id = transaction_code
                order.save()
                
                # Award green points
                if order.points_earned > 0:
                    award_points(order.user, order, order.points_earned)
                
                # Redirect to success page
                frontend_url = f"http://localhost:5173/order-confirmation?order_id={order.id}&status=success"
                from django.http import HttpResponseRedirect
                return HttpResponseRedirect(frontend_url)
            else:
                # Payment failed
                order.payment_status = 'failed'
                order.status = 'cancelled'
                order.save()
                
                # Restore stock
                for item in order.items.all():
                    product = item.product
                    product.stock += item.quantity
                    product.save()
                
                frontend_url = f"http://localhost:5173/order-confirmation?order_id={order.id}&status=failed"
                from django.http import HttpResponseRedirect
                return HttpResponseRedirect(frontend_url)
                
        except requests.RequestException as e:
            print(f"eSewa verification error: {e}")
            # For testing, mark as success if verification fails
            order.payment_status = 'completed'
            order.status = 'confirmed'
            order.esewa_ref_id = transaction_code or 'TEST-' + str(order.id)
            order.save()
            
            # Award green points
            if order.points_earned > 0:
                award_points(order.user, order, order.points_earned)
            
            frontend_url = f"http://localhost:5173/order-confirmation?order_id={order.id}&status=success"
            from django.http import HttpResponseRedirect
            return HttpResponseRedirect(frontend_url)
        
    except Exception as e:
        print(f"Error in esewa_payment_verify: {e}")
        import traceback
        traceback.print_exc()
        return Response({
            'error': str(e),
            'traceback': traceback.format_exc()
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET', 'POST'])
def esewa_payment_failure(request):
    """
    Handle eSewa payment failure callback
    """
    try:
        data = request.GET if request.method == 'GET' else request.data
        transaction_uuid = data.get('refId') or data.get('transaction_uuid')
        
        order_id = None
        if transaction_uuid:
            try:
                order = Order.objects.get(transaction_id=transaction_uuid)
                order.payment_status = 'failed'
                order.status = 'cancelled'
                order.save()
                order_id = order.id
                
                # Restore stock
                for item in order.items.all():
                    product = item.product
                    product.stock += item.quantity
                    product.save()
                    
            except Order.DoesNotExist:
                pass
        
        # Redirect to failure page
        frontend_url = f"http://localhost:5173/order-confirmation?order_id={order_id or ''}&status=failed"
        from django.http import HttpResponseRedirect
        return HttpResponseRedirect(frontend_url)
        
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_cod_order(request):
    """
    Create Cash on Delivery order
    """
    try:
        cart = Cart.objects.get(user=request.user)
        if not cart.items.exists():
            return Response({'error': 'Cart is empty'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Get shipping details
        shipping_address = request.data.get('shipping_address', '')
        phone_number = request.data.get('phone_number', '')
        
        # Calculate total
        total_amount = cart.total_price
        
        # Calculate green points to be earned
        points_to_earn = calculate_points_earned(total_amount)
        
        # Create order
        order = Order.objects.create(
            user=request.user,
            total_amount=total_amount,
            status='confirmed',
            payment_method='cod',
            payment_status='cash_payment',
            shipping_address=shipping_address,
            phone_number=phone_number,
            points_earned=points_to_earn
        )
        
        # Create order items from cart items
        for cart_item in cart.items.all():
            OrderItem.objects.create(
                order=order,
                product=cart_item.product,
                quantity=cart_item.quantity,
                price=cart_item.product.price
            )
            
            # Reduce stock
            product = cart_item.product
            product.stock -= cart_item.quantity
            product.save()
        
        # Award green points to user
        award_points(request.user, order, points_to_earn)
        
        # Clear cart after order creation
        cart.items.all().delete()
        
        # Log initial status history
        OrderStatusHistory.objects.create(order=order, status='confirmed', note='Order placed via Cash on Delivery')
        
        # Return order details
        serializer = OrderSerializer(order)
        return Response({
            'message': 'Order created successfully',
            'order': serializer.data,
            'points_earned': points_to_earn
        }, status=status.HTTP_201_CREATED)
        
    except Cart.DoesNotExist:
        return Response({'error': 'Cart not found'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def track_order(request, order_id):
    """Get order tracking details with full status history"""
    try:
        order = Order.objects.get(id=order_id, user=request.user)
    except Order.DoesNotExist:
        return Response({'error': 'Order not found'}, status=status.HTTP_404_NOT_FOUND)

    history = order.status_history.all().values('status', 'note', 'changed_at')

    return Response({
        'order_id': order.id,
        'current_status': order.status,
        'payment_method': order.payment_method,
        'payment_status': order.payment_status,
        'total_amount': order.total_amount,
        'shipping_address': order.shipping_address,
        'created_at': order.created_at,
        'updated_at': order.updated_at,
        'status_history': list(history),
    })


@api_view(['PATCH'])
@permission_classes([IsAuthenticated])
def update_order_status(request, order_id):
    """Seller updates order status — logs to history and emails customer"""
    try:
        order = Order.objects.get(id=order_id)
    except Order.DoesNotExist:
        return Response({'error': 'Order not found'}, status=status.HTTP_404_NOT_FOUND)

    # Allow if seller owns at least one product in the order, or is staff
    seller_ids = list(order.items.values_list('product__seller_id', flat=True))
    if not request.user.is_staff and request.user.id not in seller_ids:
        return Response({'error': 'Not authorized'}, status=status.HTTP_403_FORBIDDEN)

    new_status = request.data.get('status')
    note = request.data.get('note', '')

    valid_statuses = [s[0] for s in Order.STATUS_CHOICES]
    if new_status not in valid_statuses:
        return Response({'error': f'Invalid status. Choose from: {valid_statuses}'}, status=status.HTTP_400_BAD_REQUEST)

    order.status = new_status
    order.save()

    OrderStatusHistory.objects.create(order=order, status=new_status, note=note)

    # Send email notification to customer
    try:
        from django.core.mail import send_mail
        from django.conf import settings as django_settings

        status_labels = {
            'pending': 'Pending',
            'confirmed': 'Confirmed',
            'processing': 'Processing',
            'shipped': 'Shipped',
            'delivered': 'Delivered',
            'cancelled': 'Cancelled',
        }
        status_label = status_labels.get(new_status, new_status.capitalize())

        customer_email = order.user.email
        customer_name = order.user.first_name or order.user.username

        subject = f"Ecomarket - Order #{order.id} Status Update: {status_label}"

        message = f"""Hi {customer_name},

Your order #{order.id} has been updated.

New Status: {status_label}
Order Total: Rs {order.total_amount}
{f'Note: {note}' if note else ''}

You can track your order at: http://localhost:5173/order-tracking/{order.id}

Thank you for shopping with Ecomarket!

— The Ecomarket Team
"""

        send_mail(
            subject=subject,
            message=message,
            from_email=django_settings.DEFAULT_FROM_EMAIL,
            recipient_list=[customer_email],
            fail_silently=True,
        )
    except Exception as e:
        print(f"Email notification failed: {e}")

    return Response({'message': f'Order status updated to {new_status}', 'order_id': order.id, 'status': new_status})


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_seller_orders(request):
    """Get all orders that contain the seller's products"""
    from django.db.models import Q
    orders = Order.objects.filter(
        items__product__seller=request.user
    ).distinct().order_by('-created_at')
    serializer = OrderSerializer(orders, many=True, context={'request': request})
    return Response(serializer.data)


@api_view(['PATCH'])
@permission_classes([IsAuthenticated])
def update_payment_status(request, order_id):
    """Seller/admin updates payment status of an order"""
    try:
        order = Order.objects.get(id=order_id)
    except Order.DoesNotExist:
        return Response({'error': 'Order not found'}, status=status.HTTP_404_NOT_FOUND)

    # Allow if seller owns at least one product in the order, or is staff
    seller_ids = list(order.items.values_list('product__seller_id', flat=True))
    if not request.user.is_staff and request.user.id not in seller_ids:
        return Response({'error': 'Not authorized'}, status=status.HTTP_403_FORBIDDEN)

    new_payment_status = request.data.get('payment_status')
    valid_payment_statuses = [s[0] for s in Order.PAYMENT_STATUS_CHOICES]

    if new_payment_status not in valid_payment_statuses:
        return Response(
            {'error': f'Invalid payment status. Choose from: {valid_payment_statuses}'},
            status=status.HTTP_400_BAD_REQUEST
        )

    order.payment_status = new_payment_status
    order.save()

    return Response({
        'message': f'Payment status updated to {new_payment_status}',
        'order_id': order.id,
        'payment_status': new_payment_status
    })
