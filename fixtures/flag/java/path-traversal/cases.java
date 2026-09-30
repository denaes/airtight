File file = new File(baseDir, request.getParameter("filename"));
FileInputStream fis = new FileInputStream(baseDir + "/" + req.getParameter("userInput"));
Path path = Paths.get(uploadDir, req.getParameter("path"));
FileReader reader = new FileReader(new File("/data", req.getParameter("file")));
File file2 = new File(dir, req.getHeader("X-Filename"));
File file3 = new File(baseDir, request.getParameter("path"));
