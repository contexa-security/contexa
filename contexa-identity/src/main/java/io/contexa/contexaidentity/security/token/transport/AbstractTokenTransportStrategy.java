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
    protected static final String ACCESS_TOKEN_COOKIE_NAME = "accessToken";
    protected static final String REFRESH_TOKEN_COOKIE_NAME = "refreshToken";
    protected static final String DEFAULT_COOKIE_PATH = "/";

    protected final boolean cookieSecureFlag;
    protected final long accessTokenValidity;
    protected final long refreshTokenValidity;

    protected AbstractTokenTransportStrategy(AuthContextProperties props) {
        this.cookieSecureFlag = props != null && props.isCookieSecure();
        this.accessTokenValidity = props != null ? props.getAccessTokenValidity() : 3600000L;
        this.refreshTokenValidity = props != null ? props.getRefreshTokenValidity() : 604800000L;
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
}

