package io.contexa.contexacore.autonomous.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import io.contexa.contexacore.domain.entity.SecurityIncident;

import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;


@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SecurityIncidentDTO implements Serializable {
    private static final long serialVersionUID = 1L;

    private String incidentId;
    private String type;
    private String threatLevel;
    private String status;
    private String description;
    private String sourceIp;
    private String destinationIp;
    private String affectedUser;
    private String organizationId;
    private Double riskScore;
    private String detectedBy;
    private String detectionSource;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private LocalDateTime detectedAt;

    
    private Set<String> affectedAssets;
    private Set<String> tags;

    
    public static SecurityIncidentDTO fromEntity(SecurityIncident incident) {
        if (incident == null) {
            return null;
        }

        return SecurityIncidentDTO.builder()
                .incidentId(incident.getIncidentId())
                .type(incident.getType() != null ? incident.getType().name() : null)
                .threatLevel(incident.getThreatLevel() != null ? incident.getThreatLevel().name() : null)
                .status(incident.getStatus() != null ? incident.getStatus().name() : null)
                .description(incident.getDescription())
                .sourceIp(incident.getSourceIp())
                .destinationIp(incident.getDestinationIp())
                .affectedUser(incident.getAffectedUser())
                .organizationId(incident.getOrganizationId())
                .riskScore(incident.getRiskScore())
                .detectedBy(incident.getDetectedBy())
                .detectionSource(incident.getDetectionSource())
                .createdAt(incident.getCreatedAt())
                .updatedAt(incident.getUpdatedAt())
                .detectedAt(incident.getDetectedAt())
                
                .affectedAssets(copySetSafely(incident.getAffectedAssets()))
                .tags(copySetSafely(incident.getTags()))
                .build();
    }

    
    private static Set<String> copySetSafely(Set<String> original) {
        if (original == null) {
            return new HashSet<>();
        }
        try {
            
            original.size(); 
            return new HashSet<>(original);
        } catch (Exception e) {
            
            return new HashSet<>();
        }
    }
}