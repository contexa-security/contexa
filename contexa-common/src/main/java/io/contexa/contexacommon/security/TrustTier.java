package io.contexa.contexacommon.security;

/**
 * Trust Tier 열거형
 *
 * Zero Trust 아키텍처에서 사용자의 신뢰 수준을 나타내는 Tier
 * Trust Score에 따라 사용자 권한을 동적으로 조정합니다.
 */
public enum TrustTier {

    /**
     * TIER_1: Full Access (최고 신뢰도)
     * - Trust Score >= 0.8
     * - 모든 권한 허용
     */
    TIER_1("Full Access"),

    /**
     * TIER_2: Limited Sensitive Operations (높은 신뢰도)
     * - Trust Score >= 0.6
     * - 민감한 작업(ADMIN, DELETE, MODIFY_CRITICAL) 제외
     */
    TIER_2("Limited Sensitive Operations"),

    /**
     * TIER_3: Read-Only (보통 신뢰도)
     * - Trust Score >= 0.4
     * - 읽기 권한만 허용 (READ, VIEW, LIST)
     */
    TIER_3("Read-Only"),

    /**
     * TIER_4: Minimal Access (낮은 신뢰도)
     * - Trust Score < 0.4
     * - 최소한의 권한만 허용 (ROLE_MINIMAL, PERMISSION_VIEW_PROFILE)
     */
    TIER_4("Minimal Access");

    private final String description;

    TrustTier(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }

    /**
     * Trust Score로부터 적절한 Tier를 결정
     *
     * @param trustScore 신뢰 점수 (0.0 ~ 1.0)
     * @param thresholds Tier 임계값 설정
     * @return 해당하는 TrustTier
     */
    public static TrustTier fromScore(double trustScore,
                                      io.contexa.contexacommon.properties.SecurityTrustTierProperties.ThresholdProperties thresholds) {
        if (trustScore >= thresholds.getTier1()) {
            return TIER_1;
        }
        if (trustScore >= thresholds.getTier2()) {
            return TIER_2;
        }
        if (trustScore >= thresholds.getTier3()) {
            return TIER_3;
        }
        return TIER_4;
    }

    /**
     * String 값으로부터 TrustTier 변환 (하위 호환성)
     *
     * @param tierString "TIER_1", "TIER_2", "TIER_3", "TIER_4"
     * @return 해당하는 TrustTier
     * @throws IllegalArgumentException 유효하지 않은 tier 문자열인 경우
     */
    public static TrustTier fromString(String tierString) {
        try {
            return TrustTier.valueOf(tierString);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid TrustTier: " + tierString, e);
        }
    }
}
