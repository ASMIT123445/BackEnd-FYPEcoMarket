from django.db import models
# pylint: disable=no-member

class Product(models.Model):
    name = models.CharField(max_length=255)
    description = models.TextField()
    price = models.DecimalField(max_digits=10, decimal_places=2)
    image = models.ImageField(upload_to='product_images/')
    rating = models.FloatField(default=0)

    def __str__(self):
        return f'{self.name}'
