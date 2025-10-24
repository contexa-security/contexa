package io.contexa.contexacore.domain.entity;

import io.contexa.contexacore.utils.JpaListConverter;
import jakarta.persistence.*;

import java.util.List;

/**
 * SOAR 승인 정책을 정의하는 JPA 엔티티.
 * 어떤 액션과 심각도에 대해 어떤 승인 규칙을 적용할지 데이터베이스에 저장한다.
 */
@Entity
@Table(name = "soar_approval_policies")
public class ApprovalPolicyEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /**
     * 정책의 이름 (e.g., "Critical IP Blocking Policy")
     */
    @Column(nullable = false, unique = true)
    private String policyName;

    /**
     * 이 정책이 적용될 액션의 이름 (e.g., "blockIp").
     * null일 경우, 모든 액션에 대한 기본 정책으로 간주될 수 있다.
     */
    @Column
    private String actionName;

    /**
     * 이 정책이 적용될 위협의 심각도 (e.g., "CRITICAL", "HIGH").
     * null일 경우, 모든 심각도에 대한 기본 정책으로 간주될 수 있다.
     */
    @Column
    private String severity;

    @Column(nullable = false)
    private int requiredApprovers;

    @Convert(converter = JpaListConverter.class)
    @Lob
    @Column(columnDefinition = "TEXT")
    private List<String> requiredRoles;

    @Column(nullable = false)
    private int timeoutMinutes;

    @Column(nullable = false)
    private boolean autoApproveOnTimeout;

    // Getters and Setters
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
