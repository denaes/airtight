// new URL(request.getParameter("url")).openStream();
new URL("https://api.github.com/events").openStream();
String safeUrl = allowlist.validate(req.getParameter("target")); new URL(safeUrl).openConnection();
URI localStatus = URI.create("/internal/status");
File localFile = new File("/tmp/" + req.getParameter("filename"));
HttpRequest safeReq = HttpRequest.newBuilder().uri(URI.create("https://api.example.com/v1")).build();
