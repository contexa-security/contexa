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
public class DecisionFeedbackPayload {

    private String feedbackId;
    private String correlationId;
    private String feedbackType;
    private String adminAction;
    private Integer aiAnalysisLevel;
    private String originalAction;
    private String overriddenAction;
    private LocalDateTime feedbackTimestamp;
    private String hashedUserId;
    private Map<String, Object> attributes;
}
