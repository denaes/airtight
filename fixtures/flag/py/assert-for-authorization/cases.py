assert user.is_admin
assert request.user.is_staff, "forbidden"
assert current_user.has_perm("delete")
assert obj.is_owner(request.user)
