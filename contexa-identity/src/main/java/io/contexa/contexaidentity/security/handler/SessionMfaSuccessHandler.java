package io.contexa.contexaidentity.security.handler;

import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.token.transport.TokenTransportResult;
import io.contexa.contexaidentity.security.utils.writer.AuthResponseWriter;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * MFA 인증용 세션 기반 성공 핸들러
 *
 * FORM, REST, OTT, PASSKEY MFA 공용으로 사용
 * OAuth2/JWT 토큰이 아닌 세션 기반 인증 처리
 * MFA 완료 후 최종 인증 성공 처리
 *
 * Spring Security의 SavedRequestAwareAuthenticationSuccessHandler 참고
 */
@Slf4j
public class SessionMfaSuccessHandler extends SessionBasedSuccessHandler {

    public SessionMfaSuccessHandler(AuthResponseWriter responseWriter,
                                    AuthContextProperties authContextProperties) {
        super(responseWriter, authContextProperties);
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        onAuthenticationSuccess(request, response, authentication, null);
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication,
                                        @Nullable TokenTransportResult tokenTransportResult)
            throws IOException, ServletException {

        if (response.isCommitted()) {
            log.warn("Response already committed for MFA authentication success");
            return;
        }

        log.info("Processing session MFA authentication success for user: {}", authentication.getName());

        // 리다이렉트 URL 결정 (SavedRequest 우선, 없으면 MFA success URL)
        String targetUrl = determineTargetUrl(request, response);

        // API 요청과 일반 요청 구분 처리
        if (isApiRequest(request)) {
            // JSON 응답
            Map<String, Object> responseData = new HashMap<>();
            responseData.put("authenticated", true);
            responseData.put("username", authentication.getName());
            responseData.put("mfaCompleted", true);
            responseData.put("redirectUrl", targetUrl);
            responseData.put("stateType", "SESSION");
            responseData.put("message", "MFA 인증이 완료되었습니다.");

            responseWriter.writeSuccessResponse(response, responseData, HttpServletResponse.SC_OK);

            log.debug("Session MFA success (JSON): user={}, redirectUrl={}",
                    authentication.getName(), targetUrl);
        } else {
            // 리다이렉트
            response.sendRedirect(targetUrl);
            log.debug("Session MFA success (redirect) for user: {} to: {}",
                    authentication.getName(), targetUrl);
        }
    }

    @Override
    protected String getDefaultTargetUrl(HttpServletRequest request) {
        // MFA 성공 URL 사용
        return request.getContextPath() + authContextProperties.getUrls().getMfa().getSuccess();
    }
}
