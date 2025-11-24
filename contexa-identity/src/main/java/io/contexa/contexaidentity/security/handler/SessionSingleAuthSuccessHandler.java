package io.contexa.contexaidentity.security.handler;

import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.token.transport.TokenTransportResult;
import io.contexa.contexaidentity.security.utils.writer.AuthResponseWriter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * 단일 인증용 세션 기반 성공 핸들러
 *
 * FORM, REST, OTT, PASSKEY 공용으로 사용
 * OAuth2/JWT 토큰이 아닌 세션 기반 인증 처리
 * MFA 기능 일체 제외
 *
 * Spring Security의 SavedRequestAwareAuthenticationSuccessHandler 참고
 */
@Slf4j
public class SessionSingleAuthSuccessHandler extends SessionBasedSuccessHandler {

    public SessionSingleAuthSuccessHandler(AuthResponseWriter responseWriter,
                                          AuthContextProperties authContextProperties) {
        super(responseWriter, authContextProperties);
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        onAuthenticationSuccess(request, response, authentication, null);
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication,
                                        @Nullable TokenTransportResult providedResult) throws IOException {

        if (response.isCommitted()) {
            log.warn("Response already committed for user: {}", authentication.getName());
            return;
        }

        log.debug("Processing session single auth success for user: {}", authentication.getName());

        // SavedRequest 기반 리다이렉트 URL 결정 (부모 클래스 공통 로직)
        String targetUrl = determineTargetUrl(request, response);

        // 세션 기반 - SecurityContext는 자동 저장됨

        // API 요청과 일반 요청 구분 처리
        if (isApiRequest(request)) {
            // JSON 응답
            Map<String, Object> responseData = new HashMap<>();
            responseData.put("authenticated", true);
            responseData.put("redirectUrl", targetUrl);
            responseData.put("message", "로그인 성공!");
            responseData.put("username", authentication.getName());
            responseData.put("stateType", "SESSION");

            responseWriter.writeSuccessResponse(response, responseData, HttpServletResponse.SC_OK);
            log.debug("Session single auth success (JSON) for user: {}", authentication.getName());
        } else {
            // 리다이렉트
            response.sendRedirect(targetUrl);
            log.debug("Session single auth success (redirect) for user: {} to {}",
                     authentication.getName(), targetUrl);
        }
    }

    @Override
    protected String getDefaultTargetUrl(HttpServletRequest request) {
        // 단일 인증 성공 URL
        return request.getContextPath() + authContextProperties.getUrls().getSingle().getLoginSuccess();
    }
}
