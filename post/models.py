from django.core.validators import FileExtensionValidator, MaxLengthValidator
from django.db import models
from django.contrib.auth import get_user_model

from shared.models import BaseModel

User = get_user_model()


class Post(BaseModel):
    author = models.ForeignKey(User, on_delete=models.CASCADE, related_name='posts')
    image = models.ImageField(upload_to="post_image",
                              validators=[FileExtensionValidator(allowed_extensions=['jpeg', 'jpg', 'png'])])
    caption = models.TextField(validators=[MaxLengthValidator(2000)])

    class Meta:
        db_table = "posts"
        verbose_name = "post"
        verbose_name_plural = "posts"



