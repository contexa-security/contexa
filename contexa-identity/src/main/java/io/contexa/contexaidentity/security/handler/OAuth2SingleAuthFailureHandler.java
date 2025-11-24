package io.contexa.contexaidentity.security.handler;

import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.utils.writer.AuthResponseWriter;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;
import org.springframework.security.core.AuthenticationException;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * 단일 인증용 OAuth2 토큰 기반 실패 핸들러
 *
 * FORM, REST, OTT, PASSKEY 공용으로 사용
 * 세션 기반이 아닌 OAuth2/JWT 토큰 기반 인증 처리
 * MFA 기능 일체 제외
 */
@Slf4j
public class OAuth2SingleAuthFailureHandler extends AbstractTokenBasedFailureHandler {

    public OAuth2SingleAuthFailureHandler(AuthResponseWriter responseWriter) {
        super(responseWriter);
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException, ServletException {
        onAuthenticationFailure(request, response, exception, null, null, null);
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception, @Nullable FactorContext factorContext,
                                        @Nullable FailureType failureType, @Nullable Map<String, Object> errorDetails)
            throws IOException, ServletException {

        if (response.isCommitted()) {
            log.warn("Response already committed for authentication failure");
            return;
        }

        log.debug("Processing OAuth2 single auth failure: {}", exception.getMessage());

        // 에러 코드 및 메시지 결정
        String errorCode = "AUTHENTICATION_FAILED";
        String errorMessage = "인증에 실패했습니다. 사용자명 또는 비밀번호를 확인하세요.";

        // FailureType에 따른 에러 메시지 커스터마이징 (단일 인증용)
        if (failureType == FailureType.PRIMARY_AUTH_FAILED) {
            errorCode = "PRIMARY_AUTH_FAILED";
            errorMessage = "아이디 또는 비밀번호가 잘못되었습니다.";
        } else if (exception.getMessage() != null && !exception.getMessage().isBlank()) {
            // exception 메시지 사용
            errorMessage = exception.getMessage();
        }

        // 응답 데이터 구성 - DefaultRestLoginPageGeneratingFilter JavaScript 호환
        Map<String, Object> responseData = new HashMap<>();
        responseData.put("authenticated", false);
        responseData.put("message", errorMessage);
        responseData.put("errorCode", errorCode);

        // errorDetails가 있으면 추가
        if (errorDetails != null && !errorDetails.isEmpty()) {
            responseData.put("errorDetails", errorDetails);
        }

        // JSON 응답 작성 (부모 클래스 공통 로직 사용)
        writeErrorResponse(request, response, errorCode, errorMessage, responseData);

        log.debug("OAuth2 single auth failure response sent: errorCode={}", errorCode);
    }
}
