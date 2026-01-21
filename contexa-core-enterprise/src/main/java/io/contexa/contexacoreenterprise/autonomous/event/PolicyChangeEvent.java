package io.contexa.contexacoreenterprise.autonomous.event;

import io.contexa.contexacoreenterprise.domain.dto.PolicyDTO;
import lombok.Getter;
import org.springframework.context.ApplicationEvent;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@Getter
public class PolicyChangeEvent extends ApplicationEvent {

    private final ChangeType changeType;

    private final Long policyId;

    private final String policyName;

    private final PolicyDTO.PolicySource policySource;

    private final PolicyDTO.ApprovalStatus approvalStatus;

    private final String changedBy;

    private final LocalDateTime changedAt;

    private final String changeReason;

    private final PolicyDTO previousPolicy;

    private final PolicyDTO currentPolicy;

    private final Double confidenceScore;

    private final String aiModel;

    private final Map<String, Object> metadata;

    public enum ChangeType {
        
        CREATED,

        UPDATED,

        DELETED,

        APPROVED,

        REJECTED,

        ACTIVATED,

        DEACTIVATED,

        AI_EVOLVED
    }

    public PolicyChangeEvent(Object source, PolicyDTO policy, ChangeType changeType, String changedBy) {
        this(source, policy, null, changeType, changedBy, null);
    }

    public PolicyChangeEvent(Object source, PolicyDTO currentPolicy, PolicyDTO previousPolicy,
                            ChangeType changeType, String changedBy, String changeReason) {
        super(source);
        this.changeType = changeType;
        this.currentPolicy = currentPolicy;
        this.previousPolicy = previousPolicy;
        this.changedBy = changedBy;
        this.changeReason = changeReason;
        this.changedAt = LocalDateTime.now();

        if (currentPolicy != null) {
            this.policyId = currentPolicy.getId();
            this.policyName = currentPolicy.getName();
            this.policySource = currentPolicy.getSource();
            this.approvalStatus = currentPolicy.getApprovalStatus();
            this.confidenceScore = currentPolicy.getConfidenceScore();
            this.aiModel = currentPolicy.getAiModel();
        } else if (previousPolicy != null) {
            
            this.policyId = previousPolicy.getId();
            this.policyName = previousPolicy.getName();
            this.policySource = previousPolicy.getSource();
            this.approvalStatus = previousPolicy.getApprovalStatus();
            this.confidenceScore = previousPolicy.getConfidenceScore();
            this.aiModel = previousPolicy.getAiModel();
        } else {
            this.policyId = null;
            this.policyName = null;
            this.policySource = null;
            this.approvalStatus = null;
            this.confidenceScore = null;
            this.aiModel = null;
        }

        this.metadata = new HashMap<>();
    }

    public void addMetadata(String key, Object value) {
        this.metadata.put(key, value);
    }

    public boolean isAIGeneratedPolicyEvent() {
        return policySource == PolicyDTO.PolicySource.AI_GENERATED ||
               policySource == PolicyDTO.PolicySource.AI_EVOLVED;
    }

    public boolean isApprovalRelatedEvent() {
        return changeType == ChangeType.APPROVED || changeType == ChangeType.REJECTED;
    }

    public boolean isCriticalChange() {
        return changeType == ChangeType.DELETED ||
               changeType == ChangeType.APPROVED ||
               changeType == ChangeType.AI_EVOLVED ||
               (changeType == ChangeType.CREATED && isAIGeneratedPolicyEvent());
    }

    public Map<String, Object> getSummary() {
        Map<String, Object> summary = new HashMap<>();
        summary.put("changeType", changeType);
        summary.put("policyId", policyId);
        summary.put("policyName", policyName);
        summary.put("policySource", policySource);
        summary.put("approvalStatus", approvalStatus);
        summary.put("changedBy", changedBy);
        summary.put("changedAt", changedAt);
        summary.put("changeReason", changeReason);
        summary.put("isAIGenerated", isAIGeneratedPolicyEvent());
        summary.put("isCritical", isCriticalChange());

        if (confidenceScore != null) {
            summary.put("confidenceScore", confidenceScore);
        }
        if (aiModel != null) {
            summary.put("aiModel", aiModel);
        }
        if (!metadata.isEmpty()) {
            summary.put("metadata", metadata);
        }

        return summary;
    }

    @Override
    public String toString() {
        return String.format(
            "PolicyChangeEvent{type=%s, policy=%s, source=%s, changedBy=%s, time=%s}",
            changeType, policyName, policySource, changedBy, changedAt
        );
    }
}