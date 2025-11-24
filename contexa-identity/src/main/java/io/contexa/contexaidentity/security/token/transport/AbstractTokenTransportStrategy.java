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

    protected static final String SAME_SITE = "Strict"; // SameSite 정책은 상황에 따라 Lax 등으로 변경 고려
    protected static final boolean HTTP_ONLY = true;
    // protected static final boolean SECURE = false; // 제거

    private final boolean cookieSecureFlag; // 프로퍼티에서 주입받을 필드

    // ObjectMapper는 스레드 안전하므로 공유 가능
    protected final ObjectMapper objectMapper = new ObjectMapper();


    // 생성자에서 AuthContextProperties 또는 boolean 값을 직접 주입받도록 수정
    // 예시: AuthContextProperties를 통해 주입
    protected AbstractTokenTransportStrategy(AuthContextProperties props) {
        // 실제 프로덕션에서는 HTTPS를 강제하므로 true가 되어야 함
        // props.isCookieSecure() 와 같은 메소드가 있다고 가정
        this.cookieSecureFlag = props != null && props.isCookieSecure(); // props가 null일 경우 기본값 false
    }
    // 또는 boolean 값을 직접 주입받는 생성자
    // protected AbstractTokenTransportStrategy(boolean cookieSecureFlag) {
    //    this.cookieSecureFlag = cookieSecureFlag;
    // }


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
                .secure(this.cookieSecureFlag) // 주입받은 값 사용
                .sameSite(SAME_SITE)
                .maxAge(maxAgeSeconds)
                .build();
        response.addHeader("Set-Cookie", cookie.toString());
    }

    protected void removeCookie(HttpServletResponse response, String name, String path) {
        ResponseCookie expired = ResponseCookie.from(name, "")
                .path(path)
                .httpOnly(HTTP_ONLY)
                .secure(this.cookieSecureFlag) // 주입받은 값 사용
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
            // 실제 프로덕션에서는 더 구체적인 예외 처리 또는 로깅 필요
            throw new RuntimeException("Failed to write JSON response", e);
        }
    }
}

