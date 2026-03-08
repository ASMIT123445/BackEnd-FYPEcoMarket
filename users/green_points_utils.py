"""
Utility functions for Green Points Reward System
"""
from django.conf import settings
from .models import GreenPointsTransaction, CustomerProfile
from decimal import Decimal

def calculate_points_earned(order_total):
    """Calculate points earned based on order total"""
    rate = getattr(settings, 'GREEN_POINTS_EARN_RATE', 10)
    points = int(order_total / rate)
    return points

def calculate_points_discount(points_to_redeem):
    """Calculate discount amount from points"""
    rate = getattr(settings, 'GREEN_POINTS_REDEEM_RATE', 10)
    discount = Decimal(points_to_redeem) / Decimal(rate)
    return discount

def award_points(user, order, points):
    """Award green points to user for completed order"""
    try:
        customer_profile = user.customer_user
        customer_profile.green_points += points
        customer_profile.save()
        
        # Create transaction record
        GreenPointsTransaction.objects.create(
            user=user,
            points=points,
            transaction_type='earned',
            order=order,
            description=f"Earned {points} points from Order #{order.id}"
        )
        return True
    except Exception as e:
        print(f"Error awarding points: {e}")
        return False

def redeem_points(user, order, points):
    """Redeem green points for discount"""
    try:
        customer_profile = user.customer_user
        
        # Check if user has enough points
        if customer_profile.green_points < points:
            return False, "Insufficient points"
        
        # Check minimum redemption
        min_redeem = getattr(settings, 'GREEN_POINTS_MIN_REDEEM', 50)
        if points < min_redeem:
            return False, f"Minimum {min_redeem} points required"
        
        # Calculate discount
        discount = calculate_points_discount(points)
        
        # Check maximum discount percentage
        max_discount_percent = getattr(settings, 'GREEN_POINTS_MAX_DISCOUNT_PERCENT', 50)
        max_discount = order.total_amount * Decimal(max_discount_percent / 100)
        
        if discount > max_discount:
            return False, f"Maximum discount is {max_discount_percent}% of order total"
        
        # Deduct points
        customer_profile.green_points -= points
        customer_profile.save()
        
        # Create transaction record
        GreenPointsTransaction.objects.create(
            user=user,
            points=-points,
            transaction_type='redeemed',
            order=order,
            description=f"Redeemed {points} points for Rs {discount} discount on Order #{order.id}"
        )
        
        return True, discount
    except Exception as e:
        print(f"Error redeeming points: {e}")
        return False, str(e)
