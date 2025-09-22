# auth_project/introspection.py
# Simple token introspection and logout/blacklist handlers for Sprint 1
import json
from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

from rest_framework_simplejwt.backends import TokenBackend
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken, OutstandingToken

@csrf_exempt
def introspect(request):
    """POST { "token": "<token>" } -> { "active": true/false, "payload": {...} }"""
    if request.method != "POST":
        return JsonResponse({"detail": "method not allowed"}, status=405)
    try:
        body = json.loads(request.body.decode("utf-8") or "{}")
    except Exception:
        return JsonResponse({"active": False}, status=400)
    token = body.get("token")
    if not token:
        return JsonResponse({"active": False, "reason": "no token provided"}, status=200)
    try:
        tb = TokenBackend(signing_key=settings.SECRET_KEY, algorithm="HS256")
        payload = tb.decode(token, verify=True)
    except Exception:
        return JsonResponse({"active": False}, status=200)
    # Success: return payload so caller can make authorization decisions
    return JsonResponse({"active": True, "payload": payload}, status=200)

@api_view(["POST"])
@permission_classes([IsAuthenticated])
def logout_and_blacklist(request):
    """
    POST { "refresh": "<refresh-token>" } -> blacklist the refresh token.
    Requires an authenticated user (access token).
    """
    refresh_token = request.data.get("refresh")
    if not refresh_token:
        return Response({"detail": "refresh token required"}, status=400)
    try:
        token = RefreshToken(refresh_token)
        token.blacklist()
        return Response({"detail": "refresh token blacklisted"})
    except Exception as e:
        return Response({"error": str(e)}, status=400)
