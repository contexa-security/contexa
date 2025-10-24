package io.contexa.contexaidentity.security.core.mfa;

import jakarta.servlet.http.HttpServletRequest;

/**
 * TrustedDeviceService 기본 구현.
 * 예: "X-Device-Id" 헤더 값을 디바이스 식별자로 사용하고,
 * 이를 기준으로 단순 비교합니다.
 */
public class DefaultTrustedDeviceService implements TrustedDeviceService {
    private static final String HEADER = "X-Device-Id";
    private final java.util.Set<String> trustedDevices = new java.util.HashSet<>();

    @Override
    public boolean isTrusted(HttpServletRequest request) {
        String deviceId = request.getHeader(HEADER);
        return deviceId != null && trustedDevices.contains(deviceId);
    }

    @Override
    public String getDeviceId(HttpServletRequest request) {
        return request.getHeader(HEADER);
    }

    /** 운영 중 디바이스를 등록할 때 호출 */
    public void registerDevice(String deviceId) {
        trustedDevices.add(deviceId);
    }
}
