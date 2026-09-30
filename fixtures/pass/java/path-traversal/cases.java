// new File(baseDir, request.getParameter("filename"));
File file = new File(baseDir, request.getParameter("filename")); if (file.getCanonicalPath().startsWith(baseDir.getCanonicalPath())) { doRead(file); }
File file2 = new File(baseDir, request.getParameter("filename")); if (file2.toPath().normalize().startsWith(baseDir)) { doRead(file2); }
File file3 = new File(baseDir, FilenameUtils.getName(request.getParameter("file")));
File file4 = new File(baseDir, "static.txt");
FileInputStream stream = new FileInputStream(baseDir + "/config.properties");
Path path = Paths.get(uploadDir, "safe_document.pdf");
