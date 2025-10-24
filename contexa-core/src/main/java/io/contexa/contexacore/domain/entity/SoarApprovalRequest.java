package io.contexa.contexacore.domain.entity;

import io.contexa.contexacore.utils.JpaListConverter;
import io.contexa.contexacore.utils.JpaMapConverter;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

@Entity
@Table(name = "soar_approval_requests")
@Getter @Setter
@EntityListeners(AuditingEntityListener.class)
public class SoarApprovalRequest {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false, updatable = false)
    private String requestId;

    @Column(nullable = false, updatable = false)
    private String playbookInstanceId;  // TODO: Migrate to incidentId
    
    // 새로운 필드들 - 도메인 모델과 일치
    @Column(name = "incident_id")
    private String incidentId;  // playbookInstanceId 대체 예정
    
    @Column(name = "session_id")
    private String sessionId;
    
    @Column(name = "risk_level")
    private String riskLevel;  // CRITICAL/HIGH/MEDIUM/LOW/INFO
    
    @Column(name = "approval_type")
    private String approvalType;  // AUTO/MANUAL/SINGLE/MULTI/UNANIMOUS/EMERGENCY
    
    @Column(name = "requested_by")
    private String requestedBy;
    
    @Column(name = "approved_at")
    private LocalDateTime approvedAt;
    
    @Column(name = "action_type")
    private String actionType;
    
    @Column(name = "approval_timeout")
    private Integer approvalTimeout;

    @Column(nullable = false, updatable = false)
    private String actionName;
    
    @Column(name = "tool_name")
    private String toolName;  // actionName 대체 예정

    @Lob
    @Column(updatable = false)
    private String description;

    @Convert(converter = JpaMapConverter.class)
    @Lob
    @Column(columnDefinition = "TEXT", updatable = false)
    private Map<String, Object> parameters;

    @Column(nullable = false)
    private String status;

    @Column
    private String reviewerId;  // TODO: Migrate to approvedBy
    
    @Column(name = "approved_by")
    private String approvedBy;  // reviewerId 대체 예정
    
    private String organizationId;

    @Lob
    private String reviewerComment;  // TODO: Migrate to approvalComment
    
    @Column(name = "approval_comment")
    @Lob
    private String approvalComment;  // reviewerComment 대첲 예정

    @CreatedDate
    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @LastModifiedDate
    @Column(nullable = false)
    private LocalDateTime updatedAt;

    @Column
    private Integer requiredApprovers;

    @Convert(converter = JpaListConverter.class)
    @Lob
    @Column(columnDefinition = "TEXT")
    private List<String> requiredRoles;

}