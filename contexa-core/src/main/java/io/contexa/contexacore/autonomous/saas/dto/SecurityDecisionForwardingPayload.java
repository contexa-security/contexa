package io.contexa.contexacore.autonomous.saas.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SecurityDecisionForwardingPayload {

    private String correlationId;
    private String decision;
    private int aiAnalysisLevel;
    private long processingTimeMs;
    private String reasoning;
    private String severityLevel;
    private String eventSource;
    private LocalDateTime eventTimestamp;
    private String hashedUserId;
    private String hashedSessionId;
    private String hashedSourceIp;
    private String globalSourceKey;
    private List<String> behaviorPatterns;
    private String threatCategory;
    private String canonicalThreatClass;
    private List<String> evidenceList;
    private List<String> mitreTacticHints;
    private String targetSurfaceCategory;
    private List<String> signalTags;
    private String legitimateHypothesis;
    private String suspiciousHypothesis;
    private String requestPath;
    private String geoCountry;
    private String geoCity;
    private boolean newDevice;
    private boolean impossibleTravel;
    private double travelDistanceKm;
    private Map<String, Object> layer1Assessment;
    private Map<String, Object> layer2Assessment;
    private Map<String, Object> attributes;
    private LocalDateTime forwardedAt;
}
