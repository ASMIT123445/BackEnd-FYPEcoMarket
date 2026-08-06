from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.models import User
from users.models import SellerProfile, CustomerProfile, SellerOnboarding
from products.models import Product, ProductRating, EcoCategory, ProductCategory
from orders.models import Order
from django.db.models import Sum, Count, Avg
from django.utils import timezone
from datetime import timedelta


def admin_only(request):
    return request.user.is_authenticated and request.user.is_staff


class AdminStatsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if not admin_only(request):
            return Response({'error': 'Admin only'}, status=403)
        return Response({
            'total_users': User.objects.count(),
            'total_sellers': SellerProfile.objects.count(),
            'verified_sellers': SellerProfile.objects.filter(is_validated=True).count(),
            'pending_sellers': SellerProfile.objects.filter(is_validated=False).count(),
            'total_products': Product.objects.count(),
            'verified_products': Product.objects.filter(is_validated=True).count(),
            'pending_products': Product.objects.filter(is_validated=False).count(),
            'total_orders': Order.objects.filter(
                payment_status='completed'
            ).count() + Order.objects.filter(
                payment_method='cod', status__in=['confirmed', 'processing', 'shipped', 'delivered']
            ).count(),
            'total_revenue': float(Order.objects.filter(
                payment_status='completed'
            ).aggregate(Sum('total_amount'))['total_amount__sum'] or 0) + float(Order.objects.filter(
                payment_method='cod', status__in=['confirmed', 'processing', 'shipped', 'delivered']
            ).aggregate(Sum('total_amount'))['total_amount__sum'] or 0),
        })


class AdminUsersView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if not admin_only(request):
            return Response({'error': 'Admin only'}, status=403)
        users = User.objects.all().order_by('-date_joined')
        data = []
        for u in users:
            role = 'customer'
            try:
                if u.seller_user:
                    role = 'seller'
            except:
                pass
            data.append({
                'id': u.id, 'username': u.username, 'email': u.email,
                'first_name': u.first_name, 'last_name': u.last_name,
                'is_staff': u.is_staff, 'is_active': u.is_active,
                'date_joined': u.date_joined, 'role': role
            })
        return Response(data)

    def delete(self, request, user_id):
        if not admin_only(request):
            return Response({'error': 'Admin only'}, status=403)
        try:
            user = User.objects.get(id=user_id)
            if user.is_staff:
                return Response({'error': 'Cannot delete admin users'}, status=400)
            user.delete()
            return Response({'message': 'User deleted'})
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=404)


class AdminSellersView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if not admin_only(request):
            return Response({'error': 'Admin only'}, status=403)
        sellers = SellerProfile.objects.select_related('user').all()
        data = []
        for s in sellers:
            # Get onboarding data if exists
            onboarding = None
            try:
                ob = SellerOnboarding.objects.get(user=s.user)
                onboarding = {
                    'business_name': ob.business_name,
                    'business_type': ob.business_type,
                    'business_description': ob.business_description,
                    'store_name': ob.store_name,
                    'store_category': ob.store_category,
                    'owner_full_name': ob.owner_full_name,
                    'phone_number': ob.phone_number,
                    'business_address': ob.business_address,
                    'province': ob.province,
                    'payment_method': ob.payment_method,
                    'bank_account_name': ob.bank_account_name,
                    'bank_name': ob.bank_name,
                    'agreed_terms': ob.agreed_terms,
                    'id_proof': request.build_absolute_uri(ob.id_proof.url) if ob.id_proof else None,
                    'business_document': request.build_absolute_uri(ob.business_document.url) if ob.business_document else None,
                }
            except SellerOnboarding.DoesNotExist:
                pass

            data.append({
                'id': s.id, 'user_id': s.user.id, 'username': s.user.username,
                'email': s.user.email, 'shop_name': s.shop_name,
                'is_validated': s.is_validated, 'address': s.address,
                'onboarding': onboarding,
            })
        return Response(data)

    def patch(self, request, seller_id):
        if not admin_only(request):
            return Response({'error': 'Admin only'}, status=403)
        try:
            seller = SellerProfile.objects.get(id=seller_id)
            seller.is_validated = request.data.get('is_validated', seller.is_validated)
            seller.save()
            return Response({'message': 'Seller updated', 'is_validated': seller.is_validated})
        except SellerProfile.DoesNotExist:
            return Response({'error': 'Seller not found'}, status=404)

    def delete(self, request, seller_id):
        if not admin_only(request):
            return Response({'error': 'Admin only'}, status=403)
        try:
            seller = SellerProfile.objects.get(id=seller_id)
            seller.user.delete()
            return Response({'message': 'Seller deleted'})
        except SellerProfile.DoesNotExist:
            return Response({'error': 'Seller not found'}, status=404)


class AdminProductsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if not admin_only(request):
            return Response({'error': 'Admin only'}, status=403)
        products = Product.objects.select_related('seller', 'eco_category', 'product_category').all().order_by('-created_at')
        data = [{
            'id': p.id, 'name': p.name, 'price': float(p.price),
            'stock': p.stock, 'is_validated': p.is_validated,
            'seller': p.seller.username if p.seller else 'N/A',
            'eco_category_id': p.eco_category.id if p.eco_category else None,
            'eco_category': p.eco_category.name if p.eco_category else '—',
            'product_category_id': p.product_category.id if p.product_category else None,
            'product_category': p.product_category.name if p.product_category else '—',
            'description': p.description,
            'image_url': request.build_absolute_uri(p.image.url) if p.image else None,
            'created_at': p.created_at,
        } for p in products]
        return Response(data)

    def patch(self, request, product_id):
        if not admin_only(request):
            return Response({'error': 'Admin only'}, status=403)
        try:
            product = Product.objects.get(id=product_id)
            if 'is_validated' in request.data:
                product.is_validated = request.data['is_validated']
            if 'name' in request.data:
                product.name = request.data['name']
            if 'price' in request.data:
                product.price = request.data['price']
            if 'stock' in request.data:
                product.stock = request.data['stock']
            if 'description' in request.data:
                product.description = request.data['description']
            if 'eco_category_id' in request.data:
                try:
                    product.eco_category = EcoCategory.objects.get(id=request.data['eco_category_id'])
                except EcoCategory.DoesNotExist:
                    pass
            if 'product_category_id' in request.data:
                try:
                    product.product_category = ProductCategory.objects.get(id=request.data['product_category_id'])
                except ProductCategory.DoesNotExist:
                    pass
            product.save()
            return Response({'message': 'Product updated'})
        except Product.DoesNotExist:
            return Response({'error': 'Product not found'}, status=404)

    def delete(self, request, product_id):
        if not admin_only(request):
            return Response({'error': 'Admin only'}, status=403)
        try:
            Product.objects.get(id=product_id).delete()
            return Response({'message': 'Product deleted'})
        except Product.DoesNotExist:
            return Response({'error': 'Product not found'}, status=404)


class AdminOrdersView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if not admin_only(request):
            return Response({'error': 'Admin only'}, status=403)
        orders = Order.objects.select_related('user').all().order_by('-created_at')
        data = [{
            'id': o.id, 'customer': o.user.username, 'email': o.user.email,
            'total_amount': float(o.total_amount), 'status': o.status,
            'payment_method': o.payment_method, 'payment_status': o.payment_status,
            'created_at': o.created_at,
        } for o in orders]
        return Response(data)

    def patch(self, request, order_id):
        if not admin_only(request):
            return Response({'error': 'Admin only'}, status=403)
        try:
            order = Order.objects.get(id=order_id)
            if 'status' in request.data:
                order.status = request.data['status']
            if 'payment_status' in request.data:
                order.payment_status = request.data['payment_status']
            order.save()
            return Response({'message': 'Order updated'})
        except Order.DoesNotExist:
            return Response({'error': 'Order not found'}, status=404)

    def delete(self, request, order_id):
        if not admin_only(request):
            return Response({'error': 'Admin only'}, status=403)
        try:
            Order.objects.get(id=order_id).delete()
            return Response({'message': 'Order deleted'})
        except Order.DoesNotExist:
            return Response({'error': 'Order not found'}, status=404)


class AdminCustomersView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if not admin_only(request):
            return Response({'error': 'Admin only'}, status=403)
        customers = CustomerProfile.objects.select_related('user').all()
        data = [{
            'id': c.id,
            'user_id': c.user.id if c.user else None,
            'username': c.user.username if c.user else '—',
            'first_name': c.first_name,
            'last_name': c.last_name,
            'email': c.email,
            'address': c.address or '—',
            'green_points': c.green_points,
            'date_joined': c.user.date_joined if c.user else None,
        } for c in customers]
        return Response(data)

    def delete(self, request, customer_id):
        if not admin_only(request):
            return Response({'error': 'Admin only'}, status=403)
        try:
            c = CustomerProfile.objects.get(id=customer_id)
            c.user.delete()
            return Response({'message': 'Customer deleted'})
        except CustomerProfile.DoesNotExist:
            return Response({'error': 'Not found'}, status=404)


class AdminRatingsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if not admin_only(request):
            return Response({'error': 'Admin only'}, status=403)
        ratings = ProductRating.objects.select_related('product', 'user').all().order_by('-created_at')
        data = [{
            'id': r.id,
            'product_id': r.product.id,
            'product_name': r.product.name,
            'user': r.user.username,
            'rating': r.rating,
            'review': r.review or '—',
            'created_at': r.created_at,
        } for r in ratings]
        return Response(data)

    def delete(self, request, rating_id):
        if not admin_only(request):
            return Response({'error': 'Admin only'}, status=403)
        try:
            ProductRating.objects.get(id=rating_id).delete()
            return Response({'message': 'Rating deleted'})
        except ProductRating.DoesNotExist:
            return Response({'error': 'Not found'}, status=404)


class AdminCategoriesView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if not admin_only(request):
            return Response({'error': 'Admin only'}, status=403)
        eco = [{'id': c.id, 'type': 'Eco', 'name': c.name, 'slug': c.slug, 'is_active': c.is_active} for c in EcoCategory.objects.all()]
        prod = [{'id': c.id, 'type': 'Product', 'name': c.name, 'slug': c.slug, 'is_active': c.is_active} for c in ProductCategory.objects.all()]
        return Response(eco + prod)

    def post(self, request):
        if not admin_only(request):
            return Response({'error': 'Admin only'}, status=403)
        cat_type = request.data.get('type')
        name = request.data.get('name', '').strip()
        if not name:
            return Response({'error': 'Name required'}, status=400)
        if cat_type == 'Eco':
            c = EcoCategory.objects.create(name=name, slug=name.lower().replace(' ', '_'))
        else:
            c = ProductCategory.objects.create(name=name, slug=name.lower().replace(' ', '_'))
        return Response({'message': 'Category created', 'id': c.id}, status=201)

    def delete(self, request, cat_type, cat_id):
        if not admin_only(request):
            return Response({'error': 'Admin only'}, status=403)
        try:
            if cat_type == 'Eco':
                EcoCategory.objects.get(id=cat_id).delete()
            else:
                ProductCategory.objects.get(id=cat_id).delete()
            return Response({'message': 'Category deleted'})
        except Exception:
            return Response({'error': 'Not found'}, status=404)


class AdminChartDataView(APIView):
    """
    Returns all chart data for the admin dashboard in one request:
    - Monthly revenue (line chart) — last 6 months
    - Monthly orders (bar chart) — last 6 months
    - Seller verification status (pie chart)
    - Product verification status (pie chart)
    - Orders by payment method (bar chart)
    - Top 5 products by order count (bar chart)
    - User growth (line chart) — last 6 months
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if not (request.user.is_authenticated and request.user.is_staff):
            return Response({'error': 'Admin only'}, status=403)

        today = timezone.now()

        # ── Last 6 months labels ──────────────────────────────────
        months = []
        for i in range(5, -1, -1):
            dt = today - timedelta(days=i * 30)
            months.append({'year': dt.year, 'month': dt.month, 'label': dt.strftime('%b %Y')})

        # ── Monthly revenue & orders (last 6 months) ─────────────
        monthly_revenue = []
        monthly_orders = []
        for m in months:
            qs = Order.objects.filter(
                created_at__year=m['year'],
                created_at__month=m['month'],
            ).filter(
                payment_status='completed'
            ) | Order.objects.filter(
                created_at__year=m['year'],
                created_at__month=m['month'],
                payment_method='cod',
                status__in=['confirmed', 'processing', 'shipped', 'delivered']
            )
            rev = qs.aggregate(total=Sum('total_amount'))['total'] or 0
            monthly_revenue.append({'month': m['label'], 'revenue': float(rev)})
            monthly_orders.append({'month': m['label'], 'orders': qs.count()})

        # ── Seller verification pie ───────────────────────────────
        verified_sellers = SellerProfile.objects.filter(is_validated=True).count()
        pending_sellers = SellerProfile.objects.filter(is_validated=False).count()
        seller_pie = [
            {'name': 'Verified', 'value': verified_sellers},
            {'name': 'Pending', 'value': pending_sellers},
        ]

        # ── Product verification pie ──────────────────────────────
        verified_products = Product.objects.filter(is_validated=True).count()
        pending_products = Product.objects.filter(is_validated=False).count()
        product_pie = [
            {'name': 'Verified', 'value': verified_products},
            {'name': 'Pending', 'value': pending_products},
        ]

        # ── Orders by payment method ──────────────────────────────
        payment_methods = (
            Order.objects.values('payment_method')
            .annotate(count=Count('id'))
            .order_by('-count')
        )
        payment_bar = [
            {'method': (p['payment_method'] or 'unknown').upper(), 'orders': p['count']}
            for p in payment_methods
        ]

        # ── Top 5 products by order count ────────────────────────
        from orders.models import OrderItem
        top_products = (
            OrderItem.objects.values('product__name')
            .annotate(total_sold=Sum('quantity'))
            .order_by('-total_sold')[:5]
        )
        top_products_bar = [
            {'name': p['product__name'][:20], 'sold': p['total_sold']}
            for p in top_products
        ]

        # ── User growth (registrations per month, last 6 months) ─
        user_growth = []
        for m in months:
            count = User.objects.filter(
                date_joined__year=m['year'],
                date_joined__month=m['month'],
            ).count()
            user_growth.append({'month': m['label'], 'users': count})

        # ── Eco category distribution ─────────────────────────────
        eco_dist = (
            Product.objects.filter(eco_category__isnull=False, is_validated=True)
            .values('eco_category__name')
            .annotate(count=Count('id'))
            .order_by('-count')[:6]
        )
        eco_bar = [
            {'category': e['eco_category__name'], 'products': e['count']}
            for e in eco_dist
        ]

        return Response({
            'monthly_revenue': monthly_revenue,
            'monthly_orders': monthly_orders,
            'seller_pie': seller_pie,
            'product_pie': product_pie,
            'payment_bar': payment_bar,
            'top_products': top_products_bar,
            'user_growth': user_growth,
            'eco_distribution': eco_bar,
        })
