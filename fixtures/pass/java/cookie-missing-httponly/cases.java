// False positive cases for java/cookie-missing-httponly
import javax.servlet.http.Cookie;

public class Cases {
    public void passCases() {
        Cookie cookie = new Cookie("session", "abc");

        // Case 1: HttpOnly explicitly enabled on cookie
        cookie.setHttpOnly(true);

        // Case 2: HttpOnly explicitly enabled on sessionCookie
        Cookie sessionCookie = new Cookie("sid", "xyz");
        sessionCookie.setHttpOnly(true);

        // Case 3: Calling setSecure instead of setHttpOnly
        cookie.setSecure(true);

        // Case 4: Commented-out call with false
        // cookie.setHttpOnly(false);

        // Case 5: Non-cookie variable calling setHttpOnly
        CustomConfig element = new CustomConfig();
        element.setHttpOnly(false);

        // Case 6: Other variable setting HttpOnly
        CustomConfig pref = new CustomConfig();
        pref.setHttpOnly(false);
    }

    static class CustomConfig {
        void setHttpOnly(boolean value) {}
    }
}
