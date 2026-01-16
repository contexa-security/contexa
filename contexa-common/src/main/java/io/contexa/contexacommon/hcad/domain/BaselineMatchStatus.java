package io.contexa.contexacommon.hcad.domain;

/**
 * Baseline 비교 결과 상태
 *
 * AI Native v7.4: 매직 스트링 제거
 * - 기존: "MATCH", "PARTIAL", "MISMATCH", "UNKNOWN" 문자열
 * - 변경: Enum으로 타입 안전성 확보
 *
 * 판정 기준:
 * - MATCH: 완전 일치 (IP/Hour/UA 모두 일치)
 * - PARTIAL: 부분 일치 (같은 브라우저, 같은 OS, 다른 버전 - 자동 업데이트로 정상)
 * - MISMATCH: 불일치 (OS/디바이스 변경 = 계정 탈취 의심)
 * - UNKNOWN: 비교 불가 (데이터 없음 또는 파싱 실패)
 *
 * @author contexa
 * @since AI Native v7.4
 */
public enum BaselineMatchStatus {

    /**
     * 완전 일치
     * - IP: 동일 대역
     * - Hour: 정상 접근 시간대
     * - UA: 브라우저 + 버전 + OS 모두 일치
     */
    MATCH("MATCH", "All criteria matched"),

    /**
     * 부분 일치 (정상)
     * - UA: 같은 브라우저, 같은 OS, 다른 버전
     * - 브라우저 자동 업데이트로 인한 버전 차이는 정상
     */
    PARTIAL("PARTIAL", "Same browser and OS, version differs (normal auto-update)"),

    /**
     * 불일치 (의심)
     * - IP: 다른 대역
     * - UA: OS/디바이스 변경 (Windows -> Android 등)
     * - 계정 탈취 또는 세션 하이재킹 의심
     */
    MISMATCH("MISMATCH", "Criteria mismatch, possible account takeover"),

    /**
     * 비교 불가
     * - Baseline 데이터 없음
     * - 현재 요청 데이터 파싱 실패
     */
    UNKNOWN("UNKNOWN", "Cannot compare, data unavailable");

    private final String code;
    private final String description;

    BaselineMatchStatus(String code, String description) {
        this.code = code;
        this.description = description;
    }

    public String getCode() {
        return code;
    }

    public String getDescription() {
        return description;
    }

    /**
     * 문자열에서 Enum 변환 (하위 호환성)
     *
     * @param status 상태 문자열
     * @return BaselineMatchStatus
     */
    public static BaselineMatchStatus fromString(String status) {
        if (status == null) {
            return UNKNOWN;
        }
        for (BaselineMatchStatus s : values()) {
            if (s.code.equalsIgnoreCase(status)) {
                return s;
            }
        }
        return UNKNOWN;
    }

    /**
     * JSON 출력용 코드 반환
     */
    @Override
    public String toString() {
        return code;
    }
}
