package io.contexa.contexaidentity.security.handler.logout;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;

public interface LogoutStrategy {

    boolean supports(HttpServletRequest request, Authentication authentication);

    void execute(HttpServletRequest request, HttpServletResponse response, Authentication authentication);
}
