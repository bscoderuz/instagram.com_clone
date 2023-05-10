from rest_framework import permissions
from rest_framework.generics import CreateAPIView
from users.api.serializers import SigunUpSerializer
from .models import User


class CreateUserView(CreateAPIView):
    queryset = User.objects.all()
    permission_classes = (permissions.AllowAny,)
    serializer_class = SigunUpSerializer
