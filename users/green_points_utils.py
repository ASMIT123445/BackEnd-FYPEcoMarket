"""
Utility functions for Green Points Reward System
5 points earned per Rs 1 spent
5 points = Rs 1 discount
"""
from django.conf import settings
from .models import GreenPointsTransaction, CustomerProfile
from decimal import Decimal

def calculate_points_earned(order_total):
    """Calculate points earned: 1 point per Rs 10 spent"""
    rate = getattr(settings, 'GREEN_POINTS_EARN_RATE', 10)
    points = int(float(order_total) / rate)
    return points

def calculate_points_discount(points_to_redeem):
    """Calculate discount: 5 points = Rs 1"""
    rate = getattr(settings, 'GREEN_POINTS_REDEEM_RATE', 5)
    discount = Decimal(points_to_redeem) / Decimal(rate)
    return discount

def award_points(user, order, points):
    """Award green points to user for completed order — idempotent, won't double-award"""
    if points <= 0:
        return False
    try:
        # Only customers earn points
        customer_profile = CustomerProfile.objects.get(user=user)

        # Idempotency check — don't award twice for same order
        already_awarded = GreenPointsTransaction.objects.filter(
            user=user, order=order, transaction_type='earned'
        ).exists()
        if already_awarded:
            return False

        customer_profile.green_points += points
        customer_profile.save()

        GreenPointsTransaction.objects.create(
            user=user,
            points=points,
            transaction_type='earned',
            order=order,
            description=f"Earned {points} points from Order #{order.id}"
        )
        return True
    except CustomerProfile.DoesNotExist:
        return False
    except Exception as e:
        print(f"Error awarding points: {e}")
        return False

def redeem_points(user, order, points):
    """Redeem green points for discount"""
    try:
        points = int(points)  # ensure int
        if points <= 0:
            return False, "Points must be greater than 0"

        customer_profile = CustomerProfile.objects.get(user=user)

        if customer_profile.green_points < points:
            return False, f"Insufficient points. You have {customer_profile.green_points} points"

        min_redeem = getattr(settings, 'GREEN_POINTS_MIN_REDEEM', 50)
        if points < min_redeem:
            return False, f"Minimum {min_redeem} points required to redeem"

        discount = calculate_points_discount(points)

        max_discount_percent = getattr(settings, 'GREEN_POINTS_MAX_DISCOUNT_PERCENT', 50)
        # Use Decimal throughout to avoid TypeError
        max_discount = Decimal(str(order.total_amount)) * Decimal(str(max_discount_percent)) / Decimal('100')

        if discount > max_discount:
            return False, f"Maximum discount is {max_discount_percent}% of order total (Rs {max_discount:.2f})"

        customer_profile.green_points -= points
        customer_profile.save()

        GreenPointsTransaction.objects.create(
            user=user,
            points=-points,
            transaction_type='redeemed',
            order=order,
            description=f"Redeemed {points} points for Rs {discount} discount on Order #{order.id}"
        )

        return True, discount
    except CustomerProfile.DoesNotExist:
        return False, "Customer profile not found"
    except Exception as e:
        print(f"Error redeeming points: {e}")
        return False, str(e)
