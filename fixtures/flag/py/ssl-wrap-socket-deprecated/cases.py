s = ssl.wrap_socket(sock)
wrapped = ssl.wrap_socket(raw_socket, certfile="cert.pem")
ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
ssl_sock = ssl.wrap_socket(sock, server_side=True)
context = ssl.PROTOCOL_SSLv23
