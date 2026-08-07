# Generated manually for seller verification system
from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('users', '0011_remove_emailverification_verification_token_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='selleronboarding',
            name='is_verified',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='selleronboarding',
            name='verification_status',
            field=models.CharField(
                choices=[
                    ('pending', 'Pending Review'),
                    ('under_review', 'Under Review'),
                    ('approved', 'Approved'),
                    ('rejected', 'Rejected'),
                    ('incomplete', 'Incomplete')
                ],
                default='incomplete',
                max_length=20
            ),
        ),
        migrations.AddField(
            model_name='selleronboarding',
            name='verified_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='selleronboarding',
            name='verified_by',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name='verified_sellers',
                to=settings.AUTH_USER_MODEL
            ),
        ),
        migrations.AddField(
            model_name='selleronboarding',
            name='rejection_reason',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='selleronboarding',
            name='onboarding_completed',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='selleronboarding',
            name='completed_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AlterModelOptions(
            name='selleronboarding',
            options={'ordering': ['-created_at']},
        ),
    ]