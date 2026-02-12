package io.contexa.contexaidentity.security.handler;

import io.contexa.contexaidentity.security.token.transport.TokenTransportResult;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.Assert;

import java.io.IOException;

public interface PlatformAuthenticationSuccessHandler extends AuthenticationSuccessHandler {
    default void onAuthenticationSuccess(HttpServletRequest request,
                                 HttpServletResponse response,
                                 Authentication authentication,
                                 TokenTransportResult result) throws IOException, ServletException{

    }

    @Override
    default void onAuthenticationSuccess(HttpServletRequest request,
                                         HttpServletResponse response,
                                         Authentication authentication) throws IOException, ServletException {

    }

    default void setDefaultTargetUrl(String defaultTargetUrl) {
        Assert.isTrue(UrlUtils.isValidRedirectUrl(defaultTargetUrl),"defaultTarget must start with '/' or with 'http(s)'");
    }

    default void setAlwaysUse(boolean alwaysUse) {}
}
