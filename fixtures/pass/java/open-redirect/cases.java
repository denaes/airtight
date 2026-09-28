// False positive cases for java/open-redirect
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class Cases {
    public void passCases(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // Case 1: Static relative login path
        response.sendRedirect("/login");

        // Case 2: Static dashboard path
        response.sendRedirect("/app/dashboard");

        // Case 3: Sanitized target URL
        String safeUrl = sanitize(request.getParameter("url"));
        response.sendRedirect(safeUrl);

        // Case 4: getParameter used for data processing, not redirecting
        String id = request.getParameter("url");
        System.out.println("Processing ID: " + id);

        // Case 5: Redirect to hardcoded error page
        response.sendRedirect("/error?code=404");

        // Case 6: Comment referencing sendRedirect
        // response.sendRedirect(request.getParameter("url"));
        response.setStatus(200);
    }

    private String sanitize(String url) {
        return "/home";
    }
}
