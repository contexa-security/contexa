package io.contexa.contexacore.autonomous.event;

import lombok.Builder;
import lombok.Data;
import lombok.EqualsAndHashCode;
import org.springframework.context.ApplicationEvent;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;


@Data
@EqualsAndHashCode(callSuper = false)
public class DynamicThreatResponseEvent extends ApplicationEvent implements LearnableEvent {
    
    private final String eventId;
    private final EventType eventType = EventType.DYNAMIC_THREAT_RESPONSE;
    private final LocalDateTime occurredAt;
    private final String source;
    private final String severity;
    private final String description;
    private final Map<String, Object> context;
    private final boolean responseSuccessful;
    private final String responseDescription;
    
    
    private final String threatType;
    private final String attackVector;
    private final String targetResource;
    private final String attackerIdentity;
    private final String mitigationAction;
    private final Long incidentId;
    private final String soarWorkflowId;
    
    @Builder
    public DynamicThreatResponseEvent(
            Object eventSource,
            String severity,
            String description,
            String threatType,
            String attackVector,
            String targetResource,
            String attackerIdentity,
            String mitigationAction,
            boolean responseSuccessful,
            String responseDescription,
            Long incidentId,
            String soarWorkflowId,
            Map<String, Object> additionalContext) {
        
        super(eventSource);
        this.eventId = "DTR-" + UUID.randomUUID().toString();
        this.occurredAt = LocalDateTime.now();
        this.source = eventSource != null ? eventSource.getClass().getSimpleName() : "SecurityPlaneAgent";
        this.severity = severity != null ? severity : "HIGH";
        this.description = description;
        this.threatType = threatType;
        this.attackVector = attackVector;
        this.targetResource = targetResource;
        this.attackerIdentity = attackerIdentity;
        this.mitigationAction = mitigationAction;
        this.responseSuccessful = responseSuccessful;
        this.responseDescription = responseDescription;
        this.incidentId = incidentId;
        this.soarWorkflowId = soarWorkflowId;
        
        
        this.context = buildContext(additionalContext);
    }
    
    
    private Map<String, Object> buildContext(Map<String, Object> additionalContext) {
        Map<String, Object> ctx = new HashMap<>();
        
        
        ctx.put("threatType", threatType);
        ctx.put("attackVector", attackVector);
        ctx.put("targetResource", targetResource);
        ctx.put("attackerIdentity", attackerIdentity);
        
        
        ctx.put("mitigationAction", mitigationAction);
        ctx.put("responseSuccessful", responseSuccessful);
        ctx.put("responseDescription", responseDescription);
        
        
        ctx.put("incidentId", incidentId);
        ctx.put("soarWorkflowId", soarWorkflowId);
        ctx.put("occurredAt", occurredAt);
        
        
        if (additionalContext != null) {
            ctx.putAll(additionalContext);
        }
        
        return ctx;
    }
    
    
    public String generateNaturalLanguageDescription() {
        StringBuilder sb = new StringBuilder();
        sb.append("위협 유형: ").append(threatType).append("\n");
        sb.append("공격 벡터: ").append(attackVector).append("\n");
        sb.append("대상 리소스: ").append(targetResource).append("\n");
        sb.append("공격자: ").append(attackerIdentity).append("\n");
        sb.append("수행된 대응: ").append(mitigationAction).append("\n");
        sb.append("결과: ").append(responseSuccessful ? "성공" : "실패").append("\n");
        
        if (responseDescription != null) {
            sb.append("상세 설명: ").append(responseDescription);
        }
        
        return sb.toString();
    }
    
    
    public Map<String, String> extractLearningFeatures() {
        Map<String, String> features = new HashMap<>();
        features.put("threat_type", threatType);
        features.put("attack_vector", attackVector);
        features.put("target_type", extractResourceType(targetResource));
        features.put("attacker_type", extractAttackerType(attackerIdentity));
        features.put("mitigation_type", extractMitigationType(mitigationAction));
        features.put("severity", severity);
        features.put("success", String.valueOf(responseSuccessful));
        return features;
    }
    
    private String extractResourceType(String resource) {
        if (resource == null) return "UNKNOWN";
        if (resource.contains("api")) return "API";
        if (resource.contains("database") || resource.contains("db")) return "DATABASE";
        if (resource.contains("file")) return "FILE";
        if (resource.contains("network")) return "NETWORK";
        return "SYSTEM";
    }
    
    private String extractAttackerType(String attacker) {
        if (attacker == null) return "UNKNOWN";
        if (attacker.contains("external") || attacker.contains("IP")) return "EXTERNAL";
        if (attacker.contains("user") || attacker.contains("employee")) return "INTERNAL";
        if (attacker.contains("bot") || attacker.contains("automated")) return "AUTOMATED";
        return "UNKNOWN";
    }
    
    private String extractMitigationType(String mitigation) {
        if (mitigation == null) return "UNKNOWN";
        if (mitigation.contains("block")) return "BLOCK";
        if (mitigation.contains("isolate")) return "ISOLATE";
        if (mitigation.contains("alert")) return "ALERT";
        if (mitigation.contains("quarantine")) return "QUARANTINE";
        if (mitigation.contains("revoke")) return "REVOKE";
        return "CUSTOM";
    }
}