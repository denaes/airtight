// True positive cases for java/open-redirect
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class Cases {
    public void flagCases(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // Case 1: sendRedirect with getParameter("url")
        response.sendRedirect(request.getParameter("url"));

        // Case 2: sendRedirect with getParameter("redirect")
        response.sendRedirect(request.getParameter("redirect"));

        // Case 3: sendRedirect with getParameter("next")
        response.sendRedirect(request.getParameter("next"));

        // Case 4: sendRedirect with getParameter("dest")
        response.sendRedirect(request.getParameter("dest"));

        // Case 5: sendRedirect with getParameter("target")
        response.sendRedirect(request.getParameter("target"));
    }
}
