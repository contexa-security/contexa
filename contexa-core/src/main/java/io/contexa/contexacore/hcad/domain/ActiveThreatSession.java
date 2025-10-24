package io.contexa.contexacore.hcad.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.List;

/**
 * 활성 위협 세션
 *
 * 진행 중인 위협 활동 세션 추적
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ActiveThreatSession {
    private String sessionId;
    private String userId;
    private Instant startTime;
    private RiskLevel maxRiskLevel;
    private List<String> eventIds;
    private int incidentCount;
}
