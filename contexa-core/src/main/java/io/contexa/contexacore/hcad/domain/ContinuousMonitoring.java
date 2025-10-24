package io.contexa.contexacore.hcad.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Duration;
import java.util.List;

/**
 * 연속 모니터링 요구사항
 *
 * Zero Trust 원칙에 따른 지속적 검증 요구사항
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ContinuousMonitoring {
    private boolean required;
    private Duration monitoringDuration;
    private List<String> monitoringAspects;
    private int alertThreshold;
}
