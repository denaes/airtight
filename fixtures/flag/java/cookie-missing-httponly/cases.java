// True positive cases for java/cookie-missing-httponly
import javax.servlet.http.Cookie;

public class Cases {
    public void flagCases() {
        // Case 1: Standard cookie variable setting HttpOnly to false
        Cookie cookie = new Cookie("session", "abc");
        cookie.setHttpOnly(false);

        // Case 2: sessionCookie variable setting HttpOnly to false
        Cookie sessionCookie = new Cookie("sid", "xyz");
        sessionCookie.setHttpOnly(false);

        // Case 3: ck abbreviated variable setting HttpOnly to false
        Cookie ck = new Cookie("token", "123");
        ck.setHttpOnly(false);

        // Case 4: authCookie variable setting HttpOnly to false with whitespace
        Cookie authCookie = new Cookie("auth", "sec");
        authCookie.setHttpOnly( false );
    }
}
