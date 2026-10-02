package io.contexa.demo.identity.service;

import io.contexa.demo.identity.dto.AuthenticationProgress;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;

public interface AuthenticationView {

    String loginUrl(HttpServletRequest request);

    AuthenticationProgress inspect(Authentication authentication, HttpServletRequest request);
}
