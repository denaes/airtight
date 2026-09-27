# True-positive cases: session or authentication cookies set with httponly=False
response.set_cookie("session", session_id, httponly=False)
resp.set_cookie("token", val, httponly=False, secure=True)
response.set_cookie(key="auth", value=user_token, httponly=False)
res.set_cookie("session_id", sid, httponly=False)
self.set_cookie("jwt", jwt_token, httponly=False)
response.set_cookie("auth_token", token, max_age=86400, httponly=False)
