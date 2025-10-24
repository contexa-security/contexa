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

/**
 * SecurityIncident DTO for Redis serialization
 * Lazy loading 문제를 피하기 위한 간단한 DTO
 */
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

    // 간단한 필드들만 포함 (lazy loading 컬렉션 제외)
    private Set<String> affectedAssets;
    private Set<String> tags;

    /**
     * Entity를 DTO로 변환
     */
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
                // Lazy loading 컬렉션은 초기화되어 있는 경우만 복사
                .affectedAssets(copySetSafely(incident.getAffectedAssets()))
                .tags(copySetSafely(incident.getTags()))
                .build();
    }

    /**
     * Set을 안전하게 복사 (lazy loading 문제 방지)
     */
    private static Set<String> copySetSafely(Set<String> original) {
        if (original == null) {
            return new HashSet<>();
        }
        try {
            // Set이 초기화되어 있는지 확인
            original.size(); // 이 호출이 실패하면 lazy loading 예외 발생
            return new HashSet<>(original);
        } catch (Exception e) {
            // Lazy loading 예외 발생 시 빈 Set 반환
            return new HashSet<>();
        }
    }
}