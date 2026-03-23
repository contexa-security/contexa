package io.contexa.contexacore.autonomous.saas.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ThreatOutcomePayload {

    private String outcomeId;
    private String correlationId;
    private String outcomeType;
    private String finalDisposition;
    private String resolutionSource;
    private String originalAction;
    private String finalAction;
    private String hashedUserId;
    private String summary;
    private LocalDateTime outcomeTimestamp;
    private Map<String, Object> attributes;
}