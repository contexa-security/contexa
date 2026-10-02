package io.contexa.demo.identity.service.impl;

import io.contexa.demo.identity.dto.AuthenticationProgress;
import io.contexa.demo.identity.service.AuthenticationView;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Profile;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

@Component
@Profile("!contexa")
public class StandardAuthenticationView implements AuthenticationView {

    public String loginUrl(HttpServletRequest request) {
        return request.getContextPath() + "/login";
    }

    public AuthenticationProgress inspect(Authentication authentication, HttpServletRequest request) {
        boolean active = authentication != null && authentication.isAuthenticated() &&
                !(authentication instanceof AnonymousAuthenticationToken);
        return new AuthenticationProgress(active ? "AUTHENTICATED" : "NOT_AUTHENTICATED", null, null, null);
    }
}
