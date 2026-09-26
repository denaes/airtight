app.run(debug=False)
app.run(host="127.0.0.1", port=5000)
DEBUG = os.environ.get("DEBUG") == "1"
socketio.run(app)
DEBUG_TOOLBAR = False
app.config["DEBUG"] = False
