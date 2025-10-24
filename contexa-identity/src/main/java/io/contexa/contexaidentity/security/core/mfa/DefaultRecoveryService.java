package io.contexa.contexaidentity.security.core.mfa;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

/**
 * RecoveryService 기본 구현.
 * 이메일/SMS OTP 발송을 흉내 내고, 응답에 안내 메시지를 씁니다.
 */
public class DefaultRecoveryService implements RecoveryService {
    @Override
    public void initiateRecovery(HttpServletRequest request, HttpServletResponse response,
                                 RecoveryConfig config) throws IOException {
        // 예: 실제 시스템에서는 이메일/SMS 전송 로직이 들어갑니다.
        String emailEndpoint = config.getEmailOtpEndpoint();
        String smsEndpoint = config.getSmsOtpEndpoint();

        response.setStatus(HttpServletResponse.SC_ACCEPTED);
        response.setContentType("application/json");
        response.getWriter().write(
                "{"
                        + "\"message\":\"Recovery initiated\","
                        + "\"emailEndpoint\":\"" + emailEndpoint + "\","
                        + "\"smsEndpoint\":\"" + smsEndpoint + "\""
                        + "}"
        );
    }
}
