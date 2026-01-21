package io.contexa.contexaiam.aiam.protocol.request;

import io.contexa.contexacore.autonomous.event.StaticAccessAnalysisEvent;
import lombok.Builder;
import lombok.Data;

import java.util.List;
import java.util.Map;

@Data
@Builder
public class StaticAccessOptimizationRequest {
    private String requestId;
    private String analysisType;
    private List<StaticAccessAnalysisEvent.AccessFinding> findings;
    private String analyzedResource;
    private String analyzedUser;
    private Integer totalPermissions;
    private Integer unusedPermissions;
    private Integer overPrivilegedCount;
    private Map<String, Object> recommendations;
    private Map<String, Object> context;
    private String criticality;

    public static StaticAccessOptimizationRequest fromEvent(StaticAccessAnalysisEvent event) {
        return StaticAccessOptimizationRequest.builder()
                .analysisType(event.getAnalysisType().toString())
                .findings(event.getFindings())
                .analyzedResource(event.getAnalyzedResource())
                .analyzedUser(event.getAnalyzedUser())
                .totalPermissions(event.getTotalPermissions())
                .unusedPermissions(event.getUnusedPermissions())
                .overPrivilegedCount(event.getOverPrivilegedCount())
                .recommendations(event.getRecommendations())
                .context(event.getContext())
                .build();
    }
}