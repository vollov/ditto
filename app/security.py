from rest_framework import authentication
from rest_framework import exceptions
from jose import jwt
from jose.exceptions import JWTError
from django.contrib.auth.models import User

from settings import JWT_SECRET, JWT_SIGN_ALGORITHM, JWT_HEADER

import logging
log = logging.getLogger(__name__)

class JWTAuthentication(authentication.BaseAuthentication):
    """
    authenticate the user via authentication token
    payload = 
    {
      "user": {
        "username": "kate", ...
      },
      "exp": 1482802987
    }
    """
    keyword = JWT_HEADER
    
    def authenticate(self, request):
        token = request.META.get('HTTP_AUTHORIZATION')
        
        if not token:
            log.error('JWTAuthentication.authenticate() request does not have a token!')
            return None
        else:
            log.debug('JWTAuthentication.authenticate() request got token={0}'.format(token))
            
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=JWT_SIGN_ALGORITHM)
        except JWTError:
            log.error('JWTAuthentication.authenticate() decode() failed!')
            raise exceptions.AuthenticationFailed('JWT decode error')
        
        return (payload['user'], None)