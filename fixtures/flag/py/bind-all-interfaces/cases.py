app.run(host="0.0.0.0")
sock.bind(("0.0.0.0", 8080))
uvicorn.run(app, host="0.0.0.0", port=8000)
httpd.bind(("0.0.0.0", 80))
gunicorn_conf = {"bind": "0.0.0.0:8000", "host": "0.0.0.0"}
