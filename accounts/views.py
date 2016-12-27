from django.contrib.auth.models import User, Group
from rest_framework import viewsets
from serializers import UserSerializer, GroupSerializer

import logging
log = logging.getLogger(__name__)

class UserViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows users to be viewed or edited.
    """
    queryset = User.objects.all().order_by('-date_joined')
    serializer_class = UserSerializer


class GroupViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows groups to be viewed or edited.
    """
    queryset = Group.objects.all()
    serializer_class = GroupSerializer

    
from rest_framework.response import Response
from rest_framework.views import APIView
from app.security import JWTAuthentication
from rest_framework.permissions import IsAuthenticated

class ExampleView(APIView):
    authentication_classes = (JWTAuthentication,)
    permission_classes = (IsAuthenticated,)
    #permission_classes = (permissions.IsAuthenticatedOrReadOnly,)

    def get(self, request, format=None):
        content = {
            'user': 'martin_test',  # `django.contrib.auth.User` instance.
            'auth': 'str_auth',  # None
        }
        return Response(content)

from django.contrib.auth import authenticate, login, logout
from rest_framework import status


import datetime, time
from jose import jwt
from app.settings import JWT_SECRET,JWT_SIGN_ALGORITHM,JWT_EXPIRE_IN_MINUTE

def generateToken(user):
    
    # get current time, seconds since the epoch are UTC based
    #current_time = timegm(datetime.utcnow().utctimetuple())
    now = datetime.datetime.now()
    token_expire_at = now + datetime.timedelta(minutes = JWT_EXPIRE_IN_MINUTE)
    token_expire_in_seconds = time.mktime(token_expire_at.timetuple())
    
    # The time after which the token is invalid.
    claims = {'exp': token_expire_in_seconds, 'user': user}
    
    token = jwt.encode(claims, JWT_SECRET, algorithm=JWT_SIGN_ALGORITHM)
    return token

class LoginView(APIView):

    def post(self, request, format=None):
        data = request.data
        
        username = data.get('username', None)
        password = data.get('password', None)
        log.debug('get login post with username = {0} and password = {1}'.format(username, password))
        
        account = authenticate(username=username, password=password)

        # fail, bad login info
        if account is None:
            return Response({
                'status': 'Unauthorized',
                'message': 'username/password combination invalid.'
            }, status=status.HTTP_401_UNAUTHORIZED)

        # fail, inactive account
        if not account.is_active:
            return Response({
                'status': 'Unauthorized',
                'message': 'This account has been disabled.'
            }, status=status.HTTP_401_UNAUTHORIZED)

        # success, login and respond
        login(request, account)
        #serialized = UserSerializer(account)
        token = {'username': username}
        return Response(generateToken(token))