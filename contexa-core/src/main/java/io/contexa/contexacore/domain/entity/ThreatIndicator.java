package io.contexa.contexacore.domain.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

@Entity
@Table(name = "threat_indicators")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ThreatIndicator {
    
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "indicator_id")
    private String indicatorId;
    
    @Enumerated(EnumType.STRING)
    @Column(name = "indicator_type", nullable = false)
    private IndicatorType type;
    
    @Column(name = "indicator_value", nullable = false)
    private String value;
    
    @Enumerated(EnumType.STRING)
    @Column(name = "severity", nullable = false)
    @Builder.Default
    private Severity severity = Severity.MEDIUM;
    
    @Column(name = "confidence")
    @Builder.Default
    private Double confidence = 0.5;
    
    @Column(name = "source")
    private String source;
    
    @Column(name = "description", columnDefinition = "TEXT")
    private String description;
    
    @Column(name = "threat_actor")
    private String threatActor;
    
    @Column(name = "malware_family")
    private String malwareFamily;
    
    @Column(name = "campaign")
    private String campaign;
    
    @Enumerated(EnumType.STRING)
    @Column(name = "status")
    @Builder.Default
    private IndicatorStatus status = IndicatorStatus.ACTIVE;
    
    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;
    
    @Column(name = "first_seen")
    private LocalDateTime firstSeen;
    
    @Column(name = "last_seen")
    private LocalDateTime lastSeen;
    
    @Column(name = "expires_at")
    private LocalDateTime expiresAt;
    
    @ElementCollection
    @CollectionTable(name = "indicator_metadata", 
                     joinColumns = @JoinColumn(name = "indicator_id"))
    @MapKeyColumn(name = "meta_key")
    @Column(name = "meta_value")
    @Builder.Default
    private Map<String, String> metadata = new HashMap<>();
    
    @ElementCollection
    @CollectionTable(name = "indicator_tags", 
                     joinColumns = @JoinColumn(name = "indicator_id"))
    @Column(name = "tag")
    @Builder.Default
    private Set<String> tags = new HashSet<>();
    
    @Column(name = "mitre_attack_id")
    private String mitreAttackId;
    
    @Column(name = "mitre_tactic")
    private String mitreTactic;
    
    @Column(name = "mitre_technique")
    private String mitreTechnique;
    
    @Column(name = "detection_count")
    @Builder.Default
    private Integer detectionCount = 0;
    
    @Column(name = "false_positive_count")
    @Builder.Default
    private Integer falsePositiveCount = 0;
    
    @Column(name = "threat_score")
    @Builder.Default
    private Double threatScore = 0.0;
    
    @Column(name = "detected_at")
    private LocalDateTime detectedAt;
    
    @Column(name = "cis_control")
    private String cisControl;
    
    @Column(name = "nist_csf_category")
    private String nistCsfCategory;
    
    @Column(name = "active")
    @Builder.Default
    private Boolean active = true;
    
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;
    
    @Column(name = "campaign_id")
    private String campaignId;
    
    @Column(name = "threat_actor_id")
    private String threatActorId;
    
    @ManyToMany
    @JoinTable(
        name = "related_indicators",
        joinColumns = @JoinColumn(name = "indicator_id"),
        inverseJoinColumns = @JoinColumn(name = "related_indicator_id")
    )
    @Builder.Default
    private Set<ThreatIndicator> relatedIndicators = new HashSet<>();

    public enum IndicatorType {
        IP_ADDRESS("IP Address"),
        DOMAIN("Domain"),
        URL("URL"),
        FILE_HASH("File Hash"),
        FILE_PATH("File Path"),
        REGISTRY_KEY("Registry Key"),
        PROCESS_NAME("Process Name"),
        EMAIL_ADDRESS("Email Address"),
        USER_AGENT("User Agent"),
        CERTIFICATE("Certificate"),
        MUTEX("Mutex"),
        YARA_RULE("YARA Rule"),
        BEHAVIORAL("Behavioral Pattern"),
        UNKNOWN("Unknown"),
        PATTERN("Pattern"),
        USER_ACCOUNT("User Account"),
        COMPLIANCE("Compliance"),
        EVENT("Event");
        
        private final String description;
        
        IndicatorType(String description) {
            this.description = description;
        }
        
        public String getDescription() {
            return description;
        }
    }

    public enum Severity {
        CRITICAL("Critical", 5),
        HIGH("High", 4),
        MEDIUM("Medium", 3),
        LOW("Low", 2),
        INFO("Info", 1);
        
        private final String description;
        private final int level;
        
        Severity(String description, int level) {
            this.description = description;
            this.level = level;
        }
        
        public String getDescription() {
            return description;
        }
        
        public int getLevel() {
            return level;
        }
        
        public boolean isHigherThan(Severity other) {
            return this.level > other.level;
        }
    }

    public enum IndicatorStatus {
        ACTIVE("Active"),
        INACTIVE("Inactive"),
        EXPIRED("Expired"),
        FALSE_POSITIVE("False Positive"),
        UNDER_REVIEW("Under Review");
        
        private final String description;
        
        IndicatorStatus(String description) {
            this.description = description;
        }
        
        public String getDescription() {
            return description;
        }
    }

    public void addMetadata(String key, String value) {
        if (metadata == null) {
            metadata = new HashMap<>();
        }
        metadata.put(key, value);
    }

    public void addTag(String tag) {
        if (tags == null) {
            tags = new HashSet<>();
        }
        tags.add(tag);
    }

    public void incrementDetectionCount() {
        this.detectionCount++;
        this.lastSeen = LocalDateTime.now();
    }

    public void incrementFalsePositiveCount() {
        this.falsePositiveCount++;
        if (this.falsePositiveCount > 10) {
            this.status = IndicatorStatus.FALSE_POSITIVE;
        }
    }

    @JsonIgnore
    public boolean isExpired() {
        if (expiresAt == null) {
            return false;
        }
        return LocalDateTime.now().isAfter(expiresAt);
    }

    @JsonIgnore
    public boolean isActive() {
        return active && status == IndicatorStatus.ACTIVE && !isExpired();
    }

    public void setMitreMapping(String attackId, String tactic, String technique) {
        this.mitreAttackId = attackId;
        this.mitreTactic = tactic;
        this.mitreTechnique = technique;
    }

    public void updateConfidence(double newConfidence) {
        this.confidence = Math.max(0.0, Math.min(1.0, newConfidence));
    }
}