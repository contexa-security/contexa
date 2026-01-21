package io.contexa.contexaidentity.security.token.transport;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.properties.AuthContextProperties;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseCookie;

import java.io.IOException;

public abstract class AbstractTokenTransportStrategy {

    protected static final String SAME_SITE = "Strict"; 
    protected static final boolean HTTP_ONLY = true;

    private final boolean cookieSecureFlag; 

    protected final ObjectMapper objectMapper = new ObjectMapper();

    protected AbstractTokenTransportStrategy(AuthContextProperties props) {

        this.cookieSecureFlag = props != null && props.isCookieSecure(); 
    }

    protected String extractCookie(HttpServletRequest request, String name) {
        if (request.getCookies() == null) return null;
        for (Cookie cookie : request.getCookies()) {
            if (name.equals(cookie.getName())) {
                return cookie.getValue();
            }
        }
        return null;
    }

    protected void addCookie(HttpServletResponse response, String name, String value, int maxAgeSeconds, String path) {
        ResponseCookie cookie = ResponseCookie.from(name, value)
                .path(path)
                .httpOnly(HTTP_ONLY)
                .secure(this.cookieSecureFlag) 
                .sameSite(SAME_SITE)
                .maxAge(maxAgeSeconds)
                .build();
        response.addHeader("Set-Cookie", cookie.toString());
    }

    protected void removeCookie(HttpServletResponse response, String name, String path) {
        ResponseCookie expired = ResponseCookie.from(name, "")
                .path(path)
                .httpOnly(HTTP_ONLY)
                .secure(this.cookieSecureFlag) 
                .sameSite(SAME_SITE)
                .maxAge(0)
                .build();
        response.addHeader("Set-Cookie", expired.toString());
    }

    protected void writeJson(HttpServletResponse response, Object body) {
        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE + ";charset=UTF-8");
        try {
            objectMapper.writeValue(response.getWriter(), body);
        } catch (IOException e) {
            
            throw new RuntimeException("Failed to write JSON response", e);
        }
    }
}

