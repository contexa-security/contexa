package io.contexa.demo.entry.token;

import io.contexa.demo.entry.configuration.EntryProperties;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.HexFormat;

@Component
public class HttpOnlyVisitorTokens implements VisitorTokens {

    private final EntryProperties properties;
    private final SecureRandom random = new SecureRandom();

    public HttpOnlyVisitorTokens(EntryProperties properties) {
        this.properties = properties;
    }

    public String generate() {
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    public String read(HttpServletRequest request) {
        if (request.getCookies() == null) {
            return null;
        }
        String value = null;
        for (Cookie cookie : request.getCookies()) {
            if (properties.cookieName().equals(cookie.getName())) {
                if (value != null || !cookie.getValue().matches("[A-Za-z0-9_-]{43}")) {
                    return null;
                }
                value = cookie.getValue();
            }
        }
        return value;
    }

    public String hash(String value) {
        if (value == null) {
            return null;
        }
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception unavailable) {
            throw new IllegalStateException("SHA-256 unavailable", unavailable);
        }
    }

    public void set(HttpServletResponse response, String value, Duration lifetime) {
        response.addHeader("Set-Cookie", ResponseCookie.from(properties.cookieName(), value)
                .path("/").httpOnly(true).secure(properties.secureCookie()).sameSite("Lax")
                .maxAge(lifetime).build().toString());
    }
}
