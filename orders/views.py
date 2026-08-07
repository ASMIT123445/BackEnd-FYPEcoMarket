from django.shortcuts import render
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from django.shortcuts import get_object_or_404
from decimal import Decimal
from .models import Cart, CartItem, Order, OrderItem, OrderStatusHistory
from .serializers import CartSerializer, CartItemSerializer, OrderSerializer
from products.models import Product
from users.green_points_utils import calculate_points_earned, award_points, redeem_points
from .email_utils import (
    send_order_confirmed_email,
    send_payment_success_email,
    send_payment_failed_email,
    send_order_status_update_email,
    send_order_cancelled_email,
)

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

        total_amount = cart.total_price
        points_to_redeem = int(request.data.get('points_to_redeem', 0))
        shipping_charge = Decimal(str(request.data.get('shipping_charge', 75)))
        tax_amount = Decimal(str(request.data.get('tax_amount', 0)))
        points_discount = 0

        # Calculate total including shipping and tax
        total_amount = Decimal(str(total_amount)) + shipping_charge + tax_amount

        # Calculate green points to be earned (based on subtotal only)
        points_to_earn = calculate_points_earned(float(cart.total_price))

        # Create order first (needed for redeem_points)
        order = Order.objects.create(
            user=request.user,
            total_amount=total_amount,
            status='confirmed',
            points_earned=points_to_earn
        )

        # Redeem points if requested
        if points_to_redeem > 0:
            success, result = redeem_points(request.user, order, points_to_redeem)
            if success:
                points_discount = result
                order.points_redeemed = points_to_redeem
                order.points_discount = points_discount
                order.total_amount = Decimal(str(total_amount)) - points_discount
                order.save()
            else:
                order.delete()  # rollback order
                return Response({'error': f'Points redemption failed: {result}'}, status=status.HTTP_400_BAD_REQUEST)

        # Create order items
        for cart_item in cart.items.all():
            OrderItem.objects.create(
                order=order,
                product=cart_item.product,
                quantity=cart_item.quantity,
                price=cart_item.product.price
            )

        # Green points awarded only when payment is completed — not here

        cart.items.all().delete()

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
        points_to_redeem = int(request.data.get('points_to_redeem', 0))

        # Calculate total
        total_amount = float(cart.total_price)
        shipping_charge = float(request.data.get('shipping_charge', 75))
        tax_amount = float(request.data.get('tax_amount', 0))
        total_amount = total_amount + shipping_charge + tax_amount

        # Calculate green points to be earned (based on subtotal)
        points_to_earn = calculate_points_earned(float(cart.total_price))

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

        # Redeem points if requested
        if points_to_redeem > 0:
            success, result = redeem_points(request.user, order, points_to_redeem)
            if success:
                order.points_redeemed = points_to_redeem
                order.points_discount = result
                order.total_amount = Decimal(str(total_amount)) - result
                total_amount = float(order.total_amount)
                order.save()
            else:
                order.delete()
                return Response({'error': f'Points redemption failed: {result}'}, status=status.HTTP_400_BAD_REQUEST)
        
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

                # Send payment success email
                try:
                    send_payment_success_email(order)
                except Exception as e:
                    print(f"Payment success email failed: {e}")

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

                # Send payment failed email
                try:
                    send_payment_failed_email(order)
                except Exception as e:
                    print(f"Payment failed email error: {e}")

                frontend_url = f"http://localhost:5173/order-confirmation?order_id={order.id}&status=failed"
                from django.http import HttpResponseRedirect
                return HttpResponseRedirect(frontend_url)
                
        except requests.RequestException as e:
            print(f"eSewa verification error: {e}")
            # Verification API unreachable — cancel the order to be safe
            order.payment_status = 'failed'
            order.status = 'cancelled'
            order.save()
            for item in order.items.all():
                item.product.stock += item.quantity
                item.product.save()
            frontend_url = f"http://localhost:5173/order-confirmation?order_id={order.id}&status=failed"
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
        points_to_redeem = int(request.data.get('points_to_redeem', 0))

        # Calculate total
        total_amount = cart.total_price
        shipping_charge = Decimal(str(request.data.get('shipping_charge', 75)))
        tax_amount = Decimal(str(request.data.get('tax_amount', 0)))
        total_amount = Decimal(str(total_amount)) + shipping_charge + tax_amount

        # Calculate green points to be earned (based on subtotal)
        points_to_earn = calculate_points_earned(float(cart.total_price))

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

        # Redeem points if requested
        if points_to_redeem > 0:
            success, result = redeem_points(request.user, order, points_to_redeem)
            if success:
                order.points_redeemed = points_to_redeem
                order.points_discount = result
                order.total_amount = Decimal(str(total_amount)) - result
                order.save()
            else:
                order.delete()
                return Response({'error': f'Points redemption failed: {result}'}, status=status.HTTP_400_BAD_REQUEST)
        
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
        
        # Green points awarded only when payment is completed — not at COD order creation
        
        # Clear cart after order creation
        cart.items.all().delete()
        
        # Log initial status history
        OrderStatusHistory.objects.create(order=order, status='confirmed', note='Order placed via Cash on Delivery')

        # Send order confirmation email
        try:
            send_order_confirmed_email(order)
        except Exception as e:
            print(f"Order confirmation email failed: {e}")

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

    # Send HTML email notification to customer
    try:
        send_order_status_update_email(order, new_status, note)
    except Exception as e:
        print(f"Email notification failed: {e}")

    return Response({'message': f'Order status updated to {new_status}', 'order_id': order.id, 'status': new_status})


@api_view(['PATCH'])
@permission_classes([IsAuthenticated])
def cancel_order(request, order_id):
    """Customer cancels their own order if it's still pending or confirmed"""
    try:
        order = Order.objects.get(id=order_id, user=request.user)
    except Order.DoesNotExist:
        return Response({'error': 'Order not found'}, status=status.HTTP_404_NOT_FOUND)

    if order.status not in ('pending', 'confirmed'):
        return Response(
            {'error': f'Cannot cancel an order that is already "{order.status}".'},
            status=status.HTTP_400_BAD_REQUEST
        )

    order.status = 'cancelled'
    order.save()

    # Restore stock
    for item in order.items.all():
        product = item.product
        product.stock += item.quantity
        product.save()

    OrderStatusHistory.objects.create(order=order, status='cancelled', note='Cancelled by customer')

    # Send HTML cancellation email
    try:
        send_order_cancelled_email(order)
    except Exception as e:
        print(f"Cancellation email failed: {e}")

    return Response({'message': 'Order cancelled successfully', 'order_id': order.id})


# Khalti Payment Gateway Configuration (Sandbox)
KHALTI_SECRET_KEY = getattr(settings, 'KHALTI_SECRET_KEY', 'live_secret_key_68791341fdd94846a146f0457ff7b455')  # Test secret key
KHALTI_INITIATE_URL = 'https://dev.khalti.com/api/v2/epayment/initiate/'
KHALTI_LOOKUP_URL = 'https://dev.khalti.com/api/v2/epayment/lookup/'


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def initiate_khalti_payment(request):
    """
    Initiate Khalti payment.
    Creates an order and calls Khalti initiate API, returns payment_url.
    """
    try:
        cart = Cart.objects.get(user=request.user)
        if not cart.items.exists():
            return Response({'error': 'Cart is empty'}, status=status.HTTP_400_BAD_REQUEST)

        shipping_address = request.data.get('shipping_address', '')
        phone_number = request.data.get('phone_number', '')
        points_to_redeem = int(request.data.get('points_to_redeem', 0))

        total_amount = float(cart.total_price)
        shipping_charge = float(request.data.get('shipping_charge', 75))
        tax_amount = float(request.data.get('tax_amount', 0))
        total_amount = total_amount + shipping_charge + tax_amount

        points_to_earn = calculate_points_earned(float(cart.total_price))

        order = Order.objects.create(
            user=request.user,
            total_amount=total_amount,
            status='pending',
            payment_method='khalti',
            payment_status='pending',
            shipping_address=shipping_address,
            phone_number=phone_number,
            points_earned=points_to_earn
        )

        if points_to_redeem > 0:
            success, result = redeem_points(request.user, order, points_to_redeem)
            if success:
                order.points_redeemed = points_to_redeem
                order.points_discount = result
                order.total_amount = Decimal(str(total_amount)) - result
                total_amount = float(order.total_amount)
                order.save()
            else:
                order.delete()
                return Response({'error': f'Points redemption failed: {result}'}, status=status.HTTP_400_BAD_REQUEST)

        for cart_item in cart.items.all():
            OrderItem.objects.create(
                order=order,
                product=cart_item.product,
                quantity=cart_item.quantity,
                price=cart_item.product.price
            )
            product = cart_item.product
            product.stock -= cart_item.quantity
            product.save()

        # Amount in paisa (1 Rs = 100 paisa)
        amount_paisa = int(total_amount * 100)

        return_url = f'{request.scheme}://{request.get_host()}/api/orders/khalti/verify/?order_id={order.id}'
        website_url = 'http://localhost:5173'

        khalti_payload = {
            'return_url': return_url,
            'website_url': website_url,
            'amount': amount_paisa,
            'purchase_order_id': f'ORDER-{order.id}',
            'purchase_order_name': 'Ecomarket Order',
            'customer_info': {
                'name': f'{request.user.first_name} {request.user.last_name}'.strip() or request.user.username,
                'email': request.user.email,
                'phone': phone_number or '9800000000',
            },
        }

        headers = {
            'Authorization': f'Key {KHALTI_SECRET_KEY}',
            'Content-Type': 'application/json',
        }

        khalti_response = requests.post(KHALTI_INITIATE_URL, json=khalti_payload, headers=headers, timeout=15)
        khalti_data = khalti_response.json()

        if khalti_response.status_code != 200 or 'payment_url' not in khalti_data:
            order.delete()
            return Response({'error': 'Failed to initiate Khalti payment', 'details': khalti_data}, status=status.HTTP_400_BAD_REQUEST)

        # Store pidx for later lookup
        order.transaction_id = khalti_data['pidx']
        order.save()

        cart.items.all().delete()

        return Response({
            'message': 'Khalti payment initiated',
            'order_id': order.id,
            'payment_url': khalti_data['payment_url'],
            'pidx': khalti_data['pidx'],
        }, status=status.HTTP_201_CREATED)

    except Cart.DoesNotExist:
        return Response({'error': 'Cart not found'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
def khalti_payment_verify(request):
    """
    Khalti redirects here after payment.
    Verifies via lookup API and redirects to frontend.
    """
    from django.http import HttpResponseRedirect

    pidx = request.GET.get('pidx')
    order_id = request.GET.get('order_id')
    callback_status = request.GET.get('status', '')

    try:
        order = Order.objects.get(id=order_id)
    except Order.DoesNotExist:
        return HttpResponseRedirect(f'http://localhost:5173/order-confirmation?order_id={order_id}&status=failed')

    # User cancelled
    if callback_status == 'User canceled':
        order.payment_status = 'failed'
        order.status = 'cancelled'
        order.save()
        for item in order.items.all():
            item.product.stock += item.quantity
            item.product.save()
        return HttpResponseRedirect(f'http://localhost:5173/order-confirmation?order_id={order.id}&status=failed')

    # Lookup verification
    try:
        headers = {
            'Authorization': f'Key {KHALTI_SECRET_KEY}',
            'Content-Type': 'application/json',
        }
        lookup_response = requests.post(KHALTI_LOOKUP_URL, json={'pidx': pidx}, headers=headers, timeout=15)
        lookup_data = lookup_response.json()

        if lookup_data.get('status') == 'Completed':
            order.payment_status = 'completed'
            order.status = 'confirmed'
            order.save()
            if order.points_earned > 0:
                award_points(order.user, order, order.points_earned)
            OrderStatusHistory.objects.create(order=order, status='confirmed', note='Payment completed via Khalti')
            # Send payment success email
            try:
                send_payment_success_email(order)
            except Exception as e:
                print(f"Khalti payment success email failed: {e}")
            return HttpResponseRedirect(f'http://localhost:5173/order-confirmation?order_id={order.id}&status=success')
        else:
            order.payment_status = 'failed'
            order.status = 'cancelled'
            order.save()
            for item in order.items.all():
                item.product.stock += item.quantity
                item.product.save()
            # Send payment failed email
            try:
                send_payment_failed_email(order)
            except Exception as e:
                print(f"Khalti payment failed email error: {e}")
            return HttpResponseRedirect(f'http://localhost:5173/order-confirmation?order_id={order.id}&status=failed')

    except Exception as e:
        print(f'Khalti lookup error: {e}')
        # Lookup failed — cancel the order to be safe
        order.payment_status = 'failed'
        order.status = 'cancelled'
        order.save()
        for item in order.items.all():
            item.product.stock += item.quantity
            item.product.save()
        return HttpResponseRedirect(f'http://localhost:5173/order-confirmation?order_id={order.id}&status=failed')


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

    # Award green points only when payment is marked completed
    if new_payment_status == 'completed':
        award_points(order.user, order, order.points_earned)

    return Response({
        'message': f'Payment status updated to {new_payment_status}',
        'order_id': order.id,
        'payment_status': new_payment_status
    })


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def cancel_pending_gateway_order(request):
    """
    Called by the frontend when the user navigates back from eSewa/Khalti
    without completing payment. Cancels any pending gateway orders for this user
    and restores stock.
    """
    cancelled = []
    pending_orders = Order.objects.filter(
        user=request.user,
        payment_method__in=['esewa', 'khalti'],
        payment_status='pending',
        status='pending'
    )
    for order in pending_orders:
        order.payment_status = 'failed'
        order.status = 'cancelled'
        order.save()
        for item in order.items.all():
            item.product.stock += item.quantity
            item.product.save()
        OrderStatusHistory.objects.create(
            order=order,
            status='cancelled',
            note='Payment abandoned — user returned without completing gateway payment'
        )
        cancelled.append(order.id)

    return Response({'cancelled_orders': cancelled}, status=status.HTTP_200_OK)
