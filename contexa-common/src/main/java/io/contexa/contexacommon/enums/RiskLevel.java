package io.contexa.contexacommon.enums;

/**
 * Risk Level Enum
 *
 * <p>
 * 도구 실행 또는 작업의 위험도 레벨을 나타냅니다.
 * </p>
 *
 * @since 0.1.1
 */
public enum RiskLevel {
    /**
     * 낮음 - 안전한 작업
     */
    LOW,

    /**
     * 중간 - 일반적인 작업
     */
    MEDIUM,

    /**
     * 높음 - 주의가 필요한 작업
     */
    HIGH,

    /**
     * 매우 높음 - 위험한 작업, 승인 필요
     */
    CRITICAL
}
