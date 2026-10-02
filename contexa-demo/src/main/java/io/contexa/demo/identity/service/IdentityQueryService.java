package io.contexa.demo.identity.service;

import io.contexa.demo.identity.dto.IdentityView;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;

public interface IdentityQueryService {

    IdentityView inspect(Authentication authentication, HttpServletRequest request);
}
