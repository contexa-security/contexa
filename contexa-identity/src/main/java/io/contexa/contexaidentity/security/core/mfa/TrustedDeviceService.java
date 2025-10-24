package io.contexa.contexaidentity.security.core.mfa;

import jakarta.servlet.http.HttpServletRequest;

/**
 * "이 디바이스 기억하기" 기능을 담당하는 서비스.
 */
public interface TrustedDeviceService {
    /**
     * @param request 현재 HTTP 요청
     * @return 이 디바이스가 신뢰된 디바이스로 등록되어 있는지 여부
     */
    boolean isTrusted(HttpServletRequest request);

    /**
     * @param request 현재 HTTP 요청
     * @return 신뢰된 디바이스 식별자(ex. 쿠키나 헤더에 저장된 deviceId)
     */
    String getDeviceId(HttpServletRequest request);
}
