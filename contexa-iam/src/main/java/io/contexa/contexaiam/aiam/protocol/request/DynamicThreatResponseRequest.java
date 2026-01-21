package io.contexa.contexaiam.aiam.protocol.request;

import io.contexa.contexacore.autonomous.event.DynamicThreatResponseEvent;
import io.contexa.contexaiam.aiam.protocol.context.DynamicThreatResponseContext;
import io.contexa.contexacommon.domain.request.IAMRequest;
import io.contexa.contexacommon.enums.DiagnosisType;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class DynamicThreatResponseRequest extends IAMRequest<DynamicThreatResponseContext> {
    
    private static final String PROMPT_TEMPLATE = "dynamicThreatResponse";
    private static final DiagnosisType DIAGNOSIS_TYPE = DiagnosisType.DYNAMIC_THREAT_RESPONSE;

    private String eventId;

    private boolean enablePolicyGeneration = true;
    private boolean enableSpelExpression = true;
    private boolean requiresApproval = false;
    private int maxPolicyProposals = 3;
    
    public DynamicThreatResponseRequest(DynamicThreatResponseContext context, String promptTemplate) {
        super(context, promptTemplate, RequestPriority.CRITICAL, RequestType.ANALYSIS);
        this.withDiagnosisType(DIAGNOSIS_TYPE);
    }
    
    public DynamicThreatResponseRequest(DynamicThreatResponseContext context) {
        this(context, PROMPT_TEMPLATE);
    }

    public static DynamicThreatResponseRequest create(DynamicThreatResponseContext context) {
        return new DynamicThreatResponseRequest(context);
    }

    public static DynamicThreatResponseRequest createUrgent(DynamicThreatResponseContext context) {
        DynamicThreatResponseRequest request = new DynamicThreatResponseRequest(context);
        request.withParameter("priority", RequestPriority.CRITICAL);
        request.requiresApproval = true;
        return request;
    }

    public static DynamicThreatResponseRequest fromEvent(DynamicThreatResponseEvent event) {
        
        DynamicThreatResponseContext context = new DynamicThreatResponseContext();
        context.setEventId(event.getEventId());

        DynamicThreatResponseContext.ThreatInfo threatInfo = new DynamicThreatResponseContext.ThreatInfo();
        threatInfo.setThreatType(event.getThreatType());
        threatInfo.setAttackVector(event.getAttackVector());
        threatInfo.setTargetResource(event.getTargetResource());
        threatInfo.setAttackerIdentity(event.getAttackerIdentity());
        threatInfo.setSeverity(event.getSeverity());
        threatInfo.setOccurredAt(event.getOccurredAt());
        context.setThreatInfo(threatInfo);

        DynamicThreatResponseContext.ResponseInfo responseInfo = new DynamicThreatResponseContext.ResponseInfo();
        responseInfo.setMitigationAction(event.getMitigationAction());
        responseInfo.setSuccessful(event.isResponseSuccessful());
        responseInfo.setDescription(event.getResponseDescription());
        responseInfo.setIncidentId(event.getIncidentId());
        responseInfo.setSoarWorkflowId(event.getSoarWorkflowId());
        context.setResponseInfo(responseInfo);

        DynamicThreatResponseContext.PolicyGenerationHint hint = new DynamicThreatResponseContext.PolicyGenerationHint();
        hint.setPreferredPolicyType(inferPolicyType(event));
        hint.setScope(inferScope(event));
        hint.setPriority(calculatePriority(event));
        hint.setRequiresApproval(shouldRequireApproval(event));
        hint.setTargetAudience(inferTargetAudience(event));
        context.setHint(hint);

        if (event.getContext() != null) {
            context.setAdditionalContext(event.getContext());
        }

        context.adjustSecurityLevelBySeverity();

        DynamicThreatResponseRequest request = new DynamicThreatResponseRequest(context);
        request.setEventId(event.getEventId());
        request.requiresApproval = shouldRequireApproval(event);
        
        return request;
    }
    
    private static String inferPolicyType(DynamicThreatResponseEvent event) {
        String mitigation = event.getMitigationAction();
        if (mitigation == null) return "ACCESS_CONTROL";
        
        if (mitigation.contains("block")) return "BLOCKING";
        if (mitigation.contains("rate") || mitigation.contains("limit")) return "RATE_LIMITING";
        if (mitigation.contains("revoke") || mitigation.contains("deny")) return "ACCESS_CONTROL";
        if (mitigation.contains("isolate")) return "ISOLATION";
        return "ACCESS_CONTROL";
    }
    
    private static String inferScope(DynamicThreatResponseEvent event) {
        String target = event.getTargetResource();
        if (target == null) return "GLOBAL";
        
        if (target.contains("user") || target.contains("employee")) return "USER_SPECIFIC";
        if (target.contains("api") || target.contains("resource")) return "RESOURCE_SPECIFIC";
        return "GLOBAL";
    }

    private static Integer calculatePriority(DynamicThreatResponseEvent event) {

        return 50;
    }

    private static Boolean shouldRequireApproval(DynamicThreatResponseEvent event) {

        return true;
    }
    
    private static String inferTargetAudience(DynamicThreatResponseEvent event) {
        String attacker = event.getAttackerIdentity();
        if (attacker == null) return "ALL_USERS";
        
        if (attacker.contains("external")) return "EXTERNAL_USERS";
        if (attacker.contains("internal") || attacker.contains("employee")) return "INTERNAL_USERS";
        return "ALL_USERS";
    }
    
    @Override
    public String toString() {
        return String.format("DynamicThreatResponseRequest{id='%s', eventId='%s', context=%s}",
                getRequestId(), eventId, getContext());
    }
}