package io.contexa.contexaidentity.security.core.adapter.state.oauth2.grant;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import java.util.HashMap;
import java.util.Map;

@Slf4j
public class AuthenticatedUserGrantAuthenticationConverter implements AuthenticationConverter {

    private static final String GRANT_TYPE_VALUE = "urn:ietf:params:oauth:grant-type:authenticated-user";

    @Nullable
    @Override
    public Authentication convert(HttpServletRequest request) {
        
        String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
        if (!GRANT_TYPE_VALUE.equals(grantType)) {
            return null;
        }

        Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();

        if (clientPrincipal == null) {
            log.error("Client authentication is null - OAuth2ClientAuthenticationFilter may not have executed");
            throwError(OAuth2ErrorCodes.INVALID_CLIENT,
                    "Client authentication failed - no authentication found in SecurityContext");
        }

        if (!(clientPrincipal instanceof OAuth2ClientAuthenticationToken)) {
            log.error("Client authentication is not OAuth2ClientAuthenticationToken: {}",
                    clientPrincipal.getClass().getName());
            throwError(OAuth2ErrorCodes.INVALID_CLIENT,
                    "Client authentication failed - expected OAuth2ClientAuthenticationToken but got " +
                    clientPrincipal.getClass().getSimpleName());
        }

        OAuth2ClientAuthenticationToken clientAuth = (OAuth2ClientAuthenticationToken) clientPrincipal;
        if (!clientAuth.isAuthenticated()) {
            log.error("Client authentication token is not authenticated");
            throwError(OAuth2ErrorCodes.INVALID_CLIENT,
                    "Client authentication failed - client is not authenticated");
        }

        MultiValueMap<String, String> parameters = OAuth2EndpointUtils.getParameters(request);

        String username = parameters.getFirst("username");
        if (!StringUtils.hasText(username)) {
            throwError(OAuth2ErrorCodes.INVALID_REQUEST, "OAuth 2.0 Parameter: username");
        }

        String deviceId = parameters.getFirst("device_id");

        Map<String, Object> additionalParameters = new HashMap<>();
        parameters.forEach((key, value) -> {
            if (!key.equals(OAuth2ParameterNames.GRANT_TYPE) &&
                !key.equals(OAuth2ParameterNames.CLIENT_ID) &&
                !key.equals("username") &&
                !key.equals("device_id")) {
                additionalParameters.put(key, value.get(0));
            }
        });

        return new AuthenticatedUserGrantAuthenticationToken(
                clientPrincipal, username, deviceId, additionalParameters);
    }

    private static void throwError(String errorCode, String message) {
        OAuth2Error error = new OAuth2Error(errorCode, message,
                "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2");
        throw new OAuth2AuthenticationException(error);
    }

    private static class OAuth2EndpointUtils {
        static MultiValueMap<String, String> getParameters(HttpServletRequest request) {
            Map<String, String[]> parameterMap = request.getParameterMap();
            MultiValueMap<String, String> parameters = new org.springframework.util.LinkedMultiValueMap<>();
            parameterMap.forEach((key, values) -> {
                for (String value : values) {
                    parameters.add(key, value);
                }
            });
            return parameters;
        }
    }
}
