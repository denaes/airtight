result = eval(user_expression)
exec(compile(src, "<s>", "exec"))
value = eval(request.args["q"])
exec(payload, globals())
