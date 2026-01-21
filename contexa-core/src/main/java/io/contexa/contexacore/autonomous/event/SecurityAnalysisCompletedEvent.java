package io.contexa.contexacore.autonomous.event;

import lombok.Builder;
import lombok.Getter;
import org.springframework.context.ApplicationEvent;

import java.time.Instant;

@Getter
public class SecurityAnalysisCompletedEvent extends ApplicationEvent {

    private static final long serialVersionUID = 1L;

    private final String requestId;

    private final String userId;

    private final String action;

    private final double riskScore;

    private final double confidence;

    private final Instant completedAt;

    private final long processingTimeMs;

    private final String threatType;

    private final String threatEvidence;

    @Builder
    public SecurityAnalysisCompletedEvent(Object source,
                                          String requestId,
                                          String userId,
                                          String action,
                                          double riskScore,
                                          double confidence,
                                          Instant completedAt,
                                          long processingTimeMs,
                                          String threatType,
                                          String threatEvidence) {
        super(source);
        this.requestId = requestId;
        this.userId = userId;
        this.action = action;
        this.riskScore = riskScore;
        this.confidence = confidence;
        this.completedAt = completedAt != null ? completedAt : Instant.now();
        this.processingTimeMs = processingTimeMs;
        this.threatType = threatType;
        this.threatEvidence = threatEvidence;
    }

    public boolean requiresBlocking() {
        return "BLOCK".equalsIgnoreCase(action);
    }

    public boolean isHighRisk() {
        return "BLOCK".equalsIgnoreCase(action) || "ESCALATE".equalsIgnoreCase(action);
    }

    @Override
    public String toString() {
        return String.format("SecurityAnalysisCompletedEvent[requestId=%s, userId=%s, action=%s, riskScore=%.2f]",
            requestId, userId, action, riskScore);
    }
}
