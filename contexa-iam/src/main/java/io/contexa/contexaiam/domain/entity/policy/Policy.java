package io.contexa.contexaiam.domain.entity.policy;

import com.fasterxml.jackson.annotation.JsonManagedReference;
import jakarta.persistence.*;
import lombok.*;

import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

@Entity
@Getter @Setter @Builder
@NoArgsConstructor @AllArgsConstructor
@Table(name = "POLICY")
public class Policy implements Serializable {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String name;

    private String description;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Effect effect;

    @Column(nullable = false)
    private int priority;

    @OneToMany(mappedBy = "policy", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
    @JsonManagedReference("policy-targets")
    @Builder.Default
    private Set<PolicyTarget> targets = new HashSet<>();

    @OneToMany(mappedBy = "policy", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
    @JsonManagedReference("policy-rules")
    @Builder.Default
    private Set<PolicyRule> rules = new HashSet<>();

    @Column(length = 2048)
    private String friendlyDescription;

    
    @Enumerated(EnumType.STRING)
    @Column(name = "source", length = 50)
    @Builder.Default
    private PolicySource source = PolicySource.MANUAL;

    
    @Enumerated(EnumType.STRING)
    @Column(name = "approval_status", length = 50)
    @Builder.Default
    private ApprovalStatus approvalStatus = ApprovalStatus.NOT_REQUIRED;

    
    @Column(name = "approved_by", length = 255)
    private String approvedBy;

    
    @Column(name = "approved_at")
    private LocalDateTime approvedAt;

    
    @Column(name = "confidence_score")
    private Double confidenceScore;

    
    @Column(name = "ai_model", length = 255)
    private String aiModel;

    
    @Column(name = "created_at", nullable = false, updatable = false)
    @Builder.Default
    private LocalDateTime createdAt = LocalDateTime.now();

    
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    
    @Column(name = "is_active", nullable = false)
    @Builder.Default
    private Boolean isActive = true;

    
    public boolean getIsActive() {
        return this.isActive != null ? this.isActive : true;
    }

    
    public void setIsActive(Boolean isActive) {
        this.isActive = isActive != null ? isActive : true;
    }

    public enum Effect { ALLOW, DENY }

    
    public enum PolicySource {
        
        MANUAL,

        
        AI_GENERATED,

        
        AI_EVOLVED,

        
        IMPORTED
    }

    
    public enum ApprovalStatus {
        
        PENDING,

        
        APPROVED,

        
        REJECTED,

        
        NOT_REQUIRED
    }

    
    public void addTarget(PolicyTarget target) {
        this.targets.add(target);
        target.setPolicy(this);
    }

    
    public void addRule(PolicyRule rule) {
        this.rules.add(rule);
        rule.setPolicy(this);
    }

    
    public boolean isAIGenerated() {
        return source == PolicySource.AI_GENERATED || source == PolicySource.AI_EVOLVED;
    }

    
    public boolean requiresApproval() {
        return isAIGenerated() && approvalStatus == ApprovalStatus.PENDING;
    }

    
    public void approve(String approver) {
        this.approvalStatus = ApprovalStatus.APPROVED;
        this.approvedBy = approver;
        this.approvedAt = LocalDateTime.now();
        this.updatedAt = LocalDateTime.now();
    }

    
    public void reject(String rejector) {
        this.approvalStatus = ApprovalStatus.REJECTED;
        this.approvedBy = rejector;
        this.approvedAt = LocalDateTime.now();
        this.setIsActive(false);
        this.updatedAt = LocalDateTime.now();
    }

    
    public void activate() {
        if (approvalStatus == ApprovalStatus.APPROVED || approvalStatus == ApprovalStatus.NOT_REQUIRED) {
            this.setIsActive(true);
            this.updatedAt = LocalDateTime.now();
        }
    }

    
    public void deactivate() {
        this.setIsActive(false);
        this.updatedAt = LocalDateTime.now();
    }

    
    @PrePersist
    protected void onCreate() {
        if (this.createdAt == null) {
            this.createdAt = LocalDateTime.now();
        }
        
        if (this.isActive == null) {
            this.isActive = true;
        }
    }

    
    @PreUpdate
    protected void onUpdate() {
        this.updatedAt = LocalDateTime.now();
    }
}