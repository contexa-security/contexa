package io.contexa.contexacore.domain.entity;

import io.contexa.contexacore.utils.JpaListConverter;
import jakarta.persistence.*;

import java.util.List;

@Entity
@Table(name = "soar_approval_policies")
public class ApprovalPolicyEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 255)
    private String policyName;

    @Column(length = 255)
    private String actionName;

    @Column(length = 20)
    private String severity;

    @Column(nullable = false)
    private int requiredApprovers;

    @Convert(converter = JpaListConverter.class)
    @Column(columnDefinition = "TEXT")
    private List<String> requiredRoles;

    @Column(nullable = false)
    private int timeoutMinutes;

    @Column(nullable = false)
    private boolean autoApproveOnTimeout;

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getPolicyName() { return policyName; }
    public void setPolicyName(String policyName) { this.policyName = policyName; }
    public String getActionName() { return actionName; }
    public void setActionName(String actionName) { this.actionName = actionName; }
    public String getSeverity() { return severity; }
    public void setSeverity(String severity) { this.severity = severity; }
    public int getRequiredApprovers() { return requiredApprovers; }
    public void setRequiredApprovers(int requiredApprovers) { this.requiredApprovers = requiredApprovers; }
    public List<String> getRequiredRoles() { return requiredRoles; }
    public void setRequiredRoles(List<String> requiredRoles) { this.requiredRoles = requiredRoles; }
    public int getTimeoutMinutes() { return timeoutMinutes; }
    public void setTimeoutMinutes(int timeoutMinutes) { this.timeoutMinutes = timeoutMinutes; }
    public boolean isAutoApproveOnTimeout() { return autoApproveOnTimeout; }
    public void setAutoApproveOnTimeout(boolean autoApproveOnTimeout) { this.autoApproveOnTimeout = autoApproveOnTimeout; }
}
