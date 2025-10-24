package io.contexa.contexaidentity.security.core.mfa;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * 인증 실패 후 복구 워크플로우(이메일/SMS OTP) 시작 서비스.
 */
public interface RecoveryService {
    /**
     * @param request 현재 HTTP 요청
     * @param response HTTP 응답
     * @param config DSL로 설정된 RecoveryConfig (email/sms 엔드포인트)
     * @throws java.io.IOException
     */
    void initiateRecovery(HttpServletRequest request,
                          HttpServletResponse response,
                          RecoveryConfig config) throws java.io.IOException;
}
