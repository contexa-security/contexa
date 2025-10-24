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

/**
 * Authenticated User Grant Type을 위한 AuthenticationConverter
 *
 * <p>/oauth2/token 엔드포인트의 요청을 파싱하여
 * {@link AuthenticatedUserGrantAuthenticationToken}을 생성합니다.
 *
 * <p>필수 파라미터:
 * <ul>
 *   <li>grant_type: "urn:ietf:params:oauth:grant-type:authenticated-user"</li>
 *   <li>username: 인증된 사용자 이름</li>
 * </ul>
 *
 * <p>선택 파라미터:
 * <ul>
 *   <li>device_id: 디바이스 식별자</li>
 * </ul>
 *
 * @since 2024.12
 */
@Slf4j
public class AuthenticatedUserGrantAuthenticationConverter implements AuthenticationConverter {

    private static final String GRANT_TYPE_VALUE = "urn:ietf:params:oauth:grant-type:authenticated-user";

    @Nullable
    @Override
    public Authentication convert(HttpServletRequest request) {
        // grant_type 파라미터 확인
        String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
        if (!GRANT_TYPE_VALUE.equals(grantType)) {
            return null;
        }

        // 클라이언트 인증 정보 추출 및 검증
        Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();

        if (log.isDebugEnabled()) {
            log.debug("SecurityContext authentication: {}",
                    clientPrincipal != null ? clientPrincipal.getClass().getSimpleName() : "null");
        }

        // OAuth2ClientAuthenticationToken 타입 검증
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

        if (log.isDebugEnabled()) {
            log.debug("Client authentication successful: clientId={}",
                    clientAuth.getRegisteredClient() != null ?
                    clientAuth.getRegisteredClient().getClientId() : "unknown");
        }

        // 파라미터 추출
        MultiValueMap<String, String> parameters = OAuth2EndpointUtils.getParameters(request);

        // username 필수 검증
        String username = parameters.getFirst("username");
        if (!StringUtils.hasText(username)) {
            throwError(OAuth2ErrorCodes.INVALID_REQUEST, "OAuth 2.0 Parameter: username");
        }

        // device_id (선택적)
        String deviceId = parameters.getFirst("device_id");

        // 추가 파라미터
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

    /**
     * OAuth2 엔드포인트 유틸리티 클래스
     */
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
