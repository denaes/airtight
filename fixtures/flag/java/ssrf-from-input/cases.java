new URL(request.getParameter("url")).openStream();
HttpURLConnection conn = (HttpURLConnection) new URL(req.getParameter("target")).openConnection();
HttpClient.newHttpClient().send(HttpRequest.newBuilder().uri(URI.create(req.getParameter("webhook"))).build(), null);
new URL(req.getParameter("callback")).openConnection();
HttpRequest.newBuilder().uri(URI.create(request.getParameter("dest"))).build();
