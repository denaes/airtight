if not user.is_admin: raise PermissionDenied()
if not request.user.is_staff: abort(403)
if not current_user.has_perm("delete"): raise HTTPException(403)
assert isinstance(payload, dict)
assert len(rows) == 3
assert response.status_code == 200
