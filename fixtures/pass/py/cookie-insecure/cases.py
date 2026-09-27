response.set_cookie("session", session_id, secure=True)
resp.set_cookie("token", val, secure=True, httponly=True)
response.set_cookie("theme", "light")
# response.set_cookie("session", session_id, secure=False)
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
is_secure = False
res.set_cookie("pref", "dark", secure=is_prod)
