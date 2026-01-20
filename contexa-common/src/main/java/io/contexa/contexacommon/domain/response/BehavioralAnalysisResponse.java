package io.contexa.contexacommon.domain.response;

import com.fasterxml.jackson.annotation.JsonSetter;
import com.fasterxml.jackson.annotation.Nulls;
import io.contexa.contexacommon.domain.request.AIResponse;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import java.util.*;


@Getter
@Setter
public class BehavioralAnalysisResponse extends IAMResponse {
    @JsonSetter(nulls = Nulls.SKIP)
    private String analysisId = UUID.randomUUID().toString();

    @JsonSetter(nulls = Nulls.SKIP)
    private String userId = "unknown";

    private double behavioralRiskScore = 0.0; 

    @JsonSetter(nulls = Nulls.SKIP)
    private RiskLevel riskLevel = RiskLevel.LOW;

    @JsonSetter(nulls = Nulls.SKIP)
    private String summary = ""; 

    @JsonSetter(nulls = Nulls.SKIP)
    private List<Anomaly> anomalies = new ArrayList<>();

    @JsonSetter(nulls = Nulls.SKIP)
    private List<Recommendation> recommendations = new ArrayList<>();

    @JsonSetter(nulls = Nulls.SKIP)
    private TimelineVisualizationData visualizationData;

    public BehavioralAnalysisResponse(String requestId, AIResponse.ExecutionStatus status) {
        super(requestId, status);
    }

    @Override
    public Object getData() {
        Map<String, Object> data = new HashMap<>();
        data.put("analysisId", analysisId);
        data.put("userId", userId);
        data.put("behavioralRiskScore", behavioralRiskScore);
        data.put("RiskLevel", riskLevel);
        data.put("summary", summary);
        data.put("anomalies", anomalies);
        data.put("recommendations", recommendations);
        return data;
    }

    @Override
    public String getResponseType() {
        return "BEHAVIOR_ANALYSIS";
    }

    public enum RiskLevel { LOW, MEDIUM, HIGH, CRITICAL }

    @Getter @Setter
    @AllArgsConstructor
    public static class Anomaly {
        private String type; 
        private String description;
    }

    @Getter @Setter
    @AllArgsConstructor
    public static class Recommendation {
        private String action; 
        private String reason;
    }

    @Getter @Setter
    public static class TimelineVisualizationData {
        private List<TimelineEvent> events;
    }

    @Getter @Setter
    public static class TimelineEvent {
        private String timestamp;
        private String type; 
        private String description;
        private boolean isAnomaly;
    }
}
