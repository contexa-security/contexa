package io.contexa.contexacore.domain.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.Builder;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;
import com.fasterxml.jackson.annotation.JsonIgnore;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Entity
@Table(name = "security_incidents")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SecurityIncident {
    
    @Id
    @Column(name = "incident_id", length = 50)
    private String incidentId;
    
    @Enumerated(EnumType.STRING)
    @Column(name = "incident_type", nullable = false)
    private IncidentType type;
    
    @Enumerated(EnumType.STRING)
    @Column(name = "threat_level", nullable = false)
    private ThreatLevel threatLevel;
    
    @Enumerated(EnumType.STRING)
    @Column(name = "incident_status", nullable = false)
    private IncidentStatus status;
    
    @Column(name = "description", columnDefinition = "TEXT")
    private String description;
    
    @Column(name = "source_ip")
    private String sourceIp;
    
    @Column(name = "destination_ip")
    private String destinationIp;
    
    @Column(name = "affected_user")
    private String affectedUser;
    
    @Column(name = "organization_id")
    private String organizationId;
    
    @Column(name = "risk_score")
    private Double riskScore;
    
    @ManyToMany(cascade = {CascadeType.PERSIST, CascadeType.MERGE}, fetch = FetchType.LAZY)
    @JoinTable(
        name = "indicator_incidents",
        joinColumns = @JoinColumn(name = "incident_id"),
        inverseJoinColumns = @JoinColumn(name = "indicator_id")
    )
    @JsonIgnore
    private List<ThreatIndicator> indicators;

    @OneToMany(mappedBy = "incident", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    @JsonIgnore
    private List<SecurityAction> actions;
    
    @ElementCollection
    @CollectionTable(name = "incident_affected_assets",
                     joinColumns = @JoinColumn(name = "incident_id"))
    @Column(name = "asset_id")
    @JsonIgnore
    private Set<String> affectedAssets;
    
    @Column(name = "detected_by")
    private String detectedBy;
    
    @Column(name = "detection_source")
    private String detectionSource;
    
    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;
    
    @UpdateTimestamp
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;
    
    @Column(name = "resolved_at")
    private LocalDateTime resolvedAt;
    
    @Column(name = "escalated_at")
    private LocalDateTime escalatedAt;
    
    @Column(name = "auto_response_enabled")
    private Boolean autoResponseEnabled;
    
    @Column(name = "requires_approval")
    private Boolean requiresApproval;
    
    @Column(name = "approval_request_id")
    private String approvalRequestId;
    
    @Column(name = "source")
    private String source;
    
    @Column(name = "detected_at")
    private LocalDateTime detectedAt;
    
    @ElementCollection
    @CollectionTable(name = "incident_tags",
                     joinColumns = @JoinColumn(name = "incident_id"))
    @Column(name = "tag")
    private Set<String> tags;
    
    @ElementCollection
    @CollectionTable(name = "incident_related_events",
                     joinColumns = @JoinColumn(name = "incident_id"))
    @Column(name = "event_id")
    private List<String> relatedEventIds;

    @Column(name = "affected_system")
    private String affectedSystem;
    
    @Column(name = "target_ip")
    private String targetIp;
    
    @Column(name = "mitre_attack_mapping")
    private String mitreAttackMapping;
    
    @Column(name = "event_count")
    private Integer eventCount;
    
    @Column(name = "last_event_time")
    private LocalDateTime lastEventTime;

    public enum IncidentType {
        INTRUSION_ATTEMPT("침입 시도"),
        MALWARE_DETECTION("악성코드 탐지"),
        DATA_EXFILTRATION("데이터 유출"),
        UNAUTHORIZED_ACCESS("비인가 접근"),
        PRIVILEGE_ESCALATION("권한 상승"),
        PHISHING_ATTEMPT("피싱 시도"),
        DOS_ATTACK("서비스 거부 공격"),
        SUSPICIOUS_ACTIVITY("의심스러운 활동"),
        POLICY_VIOLATION("정책 위반"),
        CONFIGURATION_CHANGE("설정 변경"),
        MALWARE("악성코드"),
        INTRUSION("침입"),
        DATA_BREACH("데이터 유출"),
        PHISHING("피싱"),
        OTHER("기타");
        
        private final String description;
        
        IncidentType(String description) {
            this.description = description;
        }
        
        public String getDescription() {
            return description;
        }
    }

    public enum ThreatLevel {
        CRITICAL(0.9, "치명적"),
        HIGH(0.7, "높음"),
        MEDIUM(0.5, "중간"),
        LOW(0.3, "낮음"),
        INFO(0.1, "정보");
        
        private final double score;
        private final String description;
        
        ThreatLevel(double score, String description) {
            this.score = score;
            this.description = description;
        }
        
        public double getScore() {
            return score;
        }
        
        public String getDescription() {
            return description;
        }

        public static ThreatLevel fromString(String level) {
            if (level == null) return INFO;
            return switch (level.toUpperCase()) {
                case "CRITICAL" -> CRITICAL;
                case "HIGH" -> HIGH;
                case "MEDIUM" -> MEDIUM;
                case "LOW" -> LOW;
                default -> INFO;
            };
        }
    }

    public enum IncidentStatus {
        NEW("신규"),
        INVESTIGATING("조사중"),
        CONFIRMED("확인됨"),
        CONTAINED("격리됨"),
        ERADICATED("제거됨"),
        RECOVERING("복구중"),
        RESOLVED("해결됨"),
        CLOSED("종료"),
        FALSE_POSITIVE("오탐");
        
        private final String description;
        
        IncidentStatus(String description) {
            this.description = description;
        }
        
        public String getDescription() {
            return description;
        }
        
        public boolean isActive() {
            return this != RESOLVED && this != CLOSED && this != FALSE_POSITIVE;
        }
    }

    public void addIndicator(ThreatIndicator indicator) {
        if (indicators == null) {
            indicators = new ArrayList<>();
        }
        indicators.add(indicator);
        
    }

    public void addAction(SecurityAction action) {
        if (actions == null) {
            actions = new ArrayList<>();
        }
        actions.add(action);
        
    }

    public void addAffectedAsset(String assetId) {
        if (affectedAssets == null) {
            affectedAssets = new HashSet<>();
        }
        affectedAssets.add(assetId);
    }

    public void addTag(String tag) {
        if (tags == null) {
            tags = new HashSet<>();
        }
        tags.add(tag);
    }

    public void addRelatedEventId(String eventId) {
        if (relatedEventIds == null) {
            relatedEventIds = new ArrayList<>();
        }
        relatedEventIds.add(eventId);
    }

    public void resolve() {
        this.status = IncidentStatus.RESOLVED;
        this.resolvedAt = LocalDateTime.now();
    }

    public void escalate() {
        this.escalatedAt = LocalDateTime.now();
        if (this.threatLevel == ThreatLevel.MEDIUM) {
            this.threatLevel = ThreatLevel.HIGH;
        } else if (this.threatLevel == ThreatLevel.HIGH) {
            this.threatLevel = ThreatLevel.CRITICAL;
        }
    }

    public boolean needsApproval() {
        
        return requiresApproval ||
               threatLevel == ThreatLevel.CRITICAL ||
               threatLevel == ThreatLevel.HIGH;
    }

    @JsonIgnore
    public boolean canAutoRespond() {
        return autoResponseEnabled && !needsApproval() && status.isActive();
    }
}