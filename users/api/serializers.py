from django.contrib.auth import authenticate
from django.contrib.auth.models import update_last_login
from django.contrib.auth.password_validation import validate_password
from django.core.validators import FileExtensionValidator
from rest_framework.generics import get_object_or_404
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer, TokenRefreshSerializer
from rest_framework_simplejwt.tokens import AccessToken
from shared.utility import check_email_or_phone, send_email, send_phone_code, check_user_type
from users.models import User, UserConfirmation, VIA_PHONE, VIA_EMAIL, NEW, CODE_VERIFIED, DONE, PHOTO_DONE
from rest_framework import exceptions
from django.db.models import Q
from rest_framework import serializers
from rest_framework.exceptions import ValidationError, PermissionDenied


class SigunUpSerializer(serializers.ModelSerializer):
    id = serializers.UUIDField(read_only=True)

    def __init__(self, *args, **kwargs):
        super(SigunUpSerializer, self).__init__(*args, **kwargs)
        self.fields['email_phone_number'] = serializers.CharField(required=False)

    class Meta:
        model = User
        fields = (
            'id',
            'auth_type',
            'auth_status',
        )
        extra_kwargs = {
            'auth_type': {"read_only": True, "required": False},
            'auth_status': {"read_only": True, "required": False}
        }

    def create(self, validated_data):
        user = super(SigunUpSerializer, self).create(validated_data)
        print(user)
        if user.auth_type == VIA_EMAIL:
            code = user.create_verify_code(VIA_EMAIL)
            send_email(user.email, code)
        elif user.auth_type == VIA_PHONE:
            code = user.create_verify_code(VIA_PHONE)
            send_email(user.phone, code)
            # send_phone_code(user.phone, code)
        user.save()
        return user

    def validate(self, data):
        super(SigunUpSerializer, self).validate(data)
        data = self.auth_validate(data)
        return data

    @staticmethod
    def auth_validate(data):
        user_input = str(data.get('email_phone_number')).lower()
        input_type = check_email_or_phone(user_input)
        if input_type == "email":
            data = {
                "email": data.get('email_phone_number'),
                "auth_type": VIA_EMAIL
            }
        elif input_type == "phone":
            data = {
                "phone": user_input,
                "auth_type": VIA_PHONE
            }
        else:
            data = {
                "success": False,
                "message": "You must send email or phone number"
            }
            return ValidationError(data)

        return data

    def validate_email_phone_number(self, value):
        value = value.lower()
        if value and User.objects.filter(email=value).exists():
            data = {
                'success': False,
                'message': "Bu email allaqachon ma'lumotlar bazasida bor"
            }
            raise ValidationError(data)
        elif value and User.objects.filter(phone=value).exists():
            data = {
                'success': False,
                'message': "Bu telefon raqami allaqachon ma'lumotlar bazasida bor"
            }
            raise ValidationError(data)

        return value

    def to_representation(self, instance):
        data = super(SigunUpSerializer, self).to_representation(instance)
        data.update(instance.token())

        return data


class ChangeUserInformation(serializers.Serializer):
    first_name = serializers.CharField(write_only=True, required=True)
    last_name = serializers.CharField(write_only=True, required=True)
    username = serializers.CharField(write_only=True, required=True)
    password = serializers.CharField(write_only=True, required=True)
    confirm_password = serializers.CharField(write_only=True, required=True)

    def validate(self, data):
        password = data.get("password", None)
        confirm_password = data.get("confirm_password", None)
        if password != confirm_password:
            raise ValidationError(
                {
                    "message": "Parolingiz va tasdiqlash parolingiz bir-biriga teng emas"
                }
            )
        if password:
            validate_password(password)
            validate_password(confirm_password)

        return data

    def validated_username(self, username):
        if len(username) < 5 or len(username) > 30:
            raise ValidationError(
                {
                    "message": "Username must be between 5 and 30 characters long"
                }
            )
        if username.isdigit():
            raise ValidationError(
                {
                    "message": "This username is entirely numeric"
                }
            )

    def validated_first_name(self, first_name):
        if len(first_name) < 5 or len(first_name) > 30:
            raise ValidationError(
                {
                    "message": "First name must be between 5 and 30 characters long"
                }
            )
        if first_name.isdigit():
            raise ValidationError(
                {
                    "message": "This first name is entirely numeric"
                }
            )

    def validated_last_name(self, last_name):
        if len(last_name) < 5 or len(last_name) > 30:
            raise ValidationError(
                {
                    "message": "Last name must be between 5 and 30 characters long"
                }
            )
        if last_name.isdigit():
            raise ValidationError(
                {
                    "message": "This last name is entirely numeric"
                }
            )

    def update(self, instance, validated_data):
        instance.first_name = validated_data.get('first_name', instance.first_name)
        instance.last_name = validated_data.get('last_name', instance.first_name)
        instance.username = validated_data.get('username', instance.username)
        instance.password = validated_data.get('password', instance.password)
        if validated_data.get('password'):
            instance.set_password(validated_data.get('password'))

        if instance.auth_status == CODE_VERIFIED:
            instance.auth_status = DONE
        instance.save()
        return instance


class ChangeUserPhotoSerializer(serializers.Serializer):
    photo = serializers.ImageField(validators=[FileExtensionValidator(allowed_extensions=[
        "jpg", "jpeg", "png", "heic", "heif",
    ])])

    def update(self, instance, validated_data):
        photo = validated_data.get('photo')
        if photo:
            instance.photo = photo
            instance.auth_status = PHOTO_DONE
            instance.save()

        return instance


class LoginSerializer(TokenObtainPairSerializer):

    def __init__(self, *args, **kwargs):
        super(LoginSerializer, self).__init__(*args, **kwargs)
        self.fields['userinput'] = serializers.CharField(required=True)
        self.fields['username'] = serializers.CharField(required=False, read_only=True)

    def auth_validate(self, data):
        user_input = data.get('userinput')  # email, phone, usernmae
        if check_user_type(user_input) == "username":
            username = user_input
        elif check_user_type(user_input) == "email":
            user = self.get_user(email__iexact=user_input)
            username = user.username
        elif check_user_type(user_input) == "phone":
            user = self.get_user(phone=user_input)
            username = user.username
        else:
            data = {
                "success": True,
                "message": "Siz email, username, yoki telefon raqam kiritishingiz kerak"
            }
            raise ValidationError(data)

        authentication_kwargs = {
            self.username_field: username,
            'password': data['password']
        }

        current_user = User.objects.filter(username__iexact=username).first()
        if current_user is not None and current_user.auth_status in [NEW, CODE_VERIFIED]:
            raise ValidationError(
                {
                    'status': False,
                    'message': "Siz hali ro'yhatdan o'tmagansiz"
                }
            )
        user = authenticate(**authentication_kwargs)
        if user is not None:
            self.user = user
        else:
            raise ValidationError(
                {
                    'status': False,
                    'message': "Sorry login or password you entered is incorrect. Place check add trg again!"
                }
            )

    def validate(self, data):
        self.auth_validate(data)
        if self.user.auth_status not in [DONE, PHOTO_DONE]:
            raise PermissionDenied("Siz login qilaolmaysiz. Ruxsatingiz yoq")
        data = self.user.token()
        data['auth_status'] = self.user.auth_status
        data['full_name'] = self.user.full_name
        return data

    def get_user(self, **kwargs):
        users = User.objects.filter(**kwargs)
        if not users.exists():
            raise ValidationError(
                {
                    "message": "No active account found"
                }
            )
        return users.first()


class LoginRefreshSerializer(TokenRefreshSerializer):

    def validate(self, attrs):
        data = super().validate(attrs)
        access_token_instance = AccessToken(data['access'])
        user_id = access_token_instance['user_id']
        user = get_object_or_404(User, id=user_id)
        update_last_login(None, user)
        return data


class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()




