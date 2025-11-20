package io.contexa.contexacore.hcad.domain;

import io.contexa.contexacommon.hcad.domain.HCADContext;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalTime;

/**
 * 임계값 계산을 위한 컨텍스트
 *
 * UnifiedThresholdManager에서 AdaptiveThresholdManager로 전달하기 위한 도메인 모델
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ThresholdContext {

    // 시간 기반 조정
    private LocalTime time;
    private String dayOfWeek;

    // 위험 기반 조정
    private String deviceType;
    private String sourceIp;
    private Boolean isNewDevice;
    private Boolean isNewLocation;

    // 신뢰 기반 조정
    private Double threatScore;
    private Boolean mfaEnabled;

    /**
     * HCADContext로부터 ThresholdContext 생성
     */
    public static ThresholdContext from(HCADContext context) {
        return ThresholdContext.builder()
            .time(LocalTime.now())
            .dayOfWeek(java.time.LocalDate.now().getDayOfWeek().toString())
            .deviceType(context.getDeviceType() != null ? context.getDeviceType() : "UNKNOWN")
            .sourceIp(context.getRemoteIp())
            .isNewDevice(context.getIsNewDevice())
            .isNewLocation(context.getIsNewLocation() != null ? context.getIsNewLocation() : false)
            .threatScore(context.getThreatScore() != null ? context.getThreatScore() : 0.0)
            .mfaEnabled(context.getHasValidMFA() != null ? context.getHasValidMFA() : false)
            .build();
    }
}
