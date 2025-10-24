package io.contexa.contexacore.hcad.domain;

/**
 * 위험 수준 열거형
 *
 * Zero Trust 아키텍처에서 사용하는 위험 등급
 */
public enum RiskLevel {
    MINIMAL,  // 최소 위험
    LOW,      // 낮은 위험
    MEDIUM,   // 중간 위험
    HIGH,     // 높은 위험
    CRITICAL  // 심각한 위험
}
