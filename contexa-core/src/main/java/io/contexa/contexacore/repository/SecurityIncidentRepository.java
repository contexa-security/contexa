package io.contexa.contexacore.repository;

import io.contexa.contexacore.domain.entity.SecurityIncident;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

public interface SecurityIncidentRepository extends JpaRepository<SecurityIncident, String> {

    @Query("SELECT i FROM SecurityIncident i WHERE i.status IN ('NEW', 'INVESTIGATING', 'CONFIRMED', 'CONTAINED', 'RECOVERING')")
    List<SecurityIncident> findActiveIncidents();

    @Query("SELECT i FROM SecurityIncident i WHERE i.organizationId = :organizationId AND i.status IN ('NEW', 'INVESTIGATING', 'CONFIRMED', 'CONTAINED', 'RECOVERING')")
    List<SecurityIncident> findActiveIncidentsByOrganization(@Param("organizationId") String organizationId);

    List<SecurityIncident> findByThreatLevel(SecurityIncident.ThreatLevel threatLevel);

    @Query("SELECT i FROM SecurityIncident i WHERE i.status = :status AND i.threatLevel IN ('HIGH', 'CRITICAL')")
    List<SecurityIncident> findHighRiskActiveIncidents(@Param("status") SecurityIncident.IncidentStatus status);

    @Query("SELECT i FROM SecurityIncident i WHERE i.createdAt BETWEEN :startDate AND :endDate")
    List<SecurityIncident> findIncidentsByDateRange(
        @Param("startDate") LocalDateTime startDate, 
        @Param("endDate") LocalDateTime endDate
    );

    @Query("SELECT i FROM SecurityIncident i WHERE i.affectedUser = :userId")
    List<SecurityIncident> findIncidentsByUser(@Param("userId") String userId);

    @Query("SELECT i FROM SecurityIncident i JOIN i.affectedAssets a WHERE a = :assetId")
    List<SecurityIncident> findIncidentsByAsset(@Param("assetId") String assetId);

    List<SecurityIncident> findByType(SecurityIncident.IncidentType type);

    @Query("SELECT i FROM SecurityIncident i WHERE i.requiresApproval = true AND i.status IN ('NEW', 'INVESTIGATING')")
    List<SecurityIncident> findIncidentsRequiringApproval();

    @Query("SELECT i FROM SecurityIncident i WHERE i.autoResponseEnabled = true AND i.requiresApproval = false AND i.status IN ('NEW', 'INVESTIGATING')")
    List<SecurityIncident> findAutoRespondableIncidents();

    @Modifying
    @Query("UPDATE SecurityIncident i SET i.status = 'CLOSED' WHERE i.createdAt < :threshold AND i.status IN ('NEW', 'INVESTIGATING')")
    int expireOldIncidents(@Param("threshold") LocalDateTime threshold);

    @Query("SELECT i FROM SecurityIncident i WHERE i.createdAt < :threshold AND i.status IN ('NEW', 'INVESTIGATING') AND i.escalatedAt IS NULL")
    List<SecurityIncident> findIncidentsNeedingEscalation(@Param("threshold") LocalDateTime threshold);

    @Query("SELECT i FROM SecurityIncident i ORDER BY i.createdAt DESC")
    List<SecurityIncident> findRecentIncidents(Pageable pageable);

    @Query("SELECT i.threatLevel, COUNT(i) FROM SecurityIncident i WHERE i.organizationId = :organizationId GROUP BY i.threatLevel")
    List<Object[]> getIncidentStatisticsByOrganization(@Param("organizationId") String organizationId);

    @Query("SELECT COUNT(i) > 0 FROM SecurityIncident i WHERE i.sourceIp = :sourceIp AND i.type = :type AND i.createdAt > :timeWindow")
    boolean existsSimilarIncident(
        @Param("sourceIp") String sourceIp, 
        @Param("type") SecurityIncident.IncidentType type,
        @Param("timeWindow") LocalDateTime timeWindow
    );

    @Modifying
    @Query("UPDATE SecurityIncident i SET i.status = :status, i.updatedAt = CURRENT_TIMESTAMP WHERE i.incidentId = :incidentId")
    int updateIncidentStatus(
        @Param("incidentId") String incidentId, 
        @Param("status") SecurityIncident.IncidentStatus status
    );

    @Modifying
    @Query("UPDATE SecurityIncident i SET i.threatLevel = :threatLevel, i.updatedAt = CURRENT_TIMESTAMP WHERE i.incidentId = :incidentId")
    int updateIncidentThreatLevel(
        @Param("incidentId") String incidentId, 
        @Param("threatLevel") SecurityIncident.ThreatLevel threatLevel
    );

    @Query("SELECT i FROM SecurityIncident i WHERE i.riskScore > :threshold AND i.status = :status")
    List<SecurityIncident> findByRiskScoreGreaterThanAndStatus(
        @Param("threshold") double threshold,
        @Param("status") String status
    );

    @Query("SELECT COUNT(i) FROM SecurityIncident i WHERE i.status = :status")
    long countByStatus(@Param("status") String status);

    @EntityGraph(attributePaths = {"tags", "relatedEventIds"})
    Optional<SecurityIncident> findWithTagsByIncidentId(String incidentId);

    @EntityGraph(attributePaths = {"tags", "relatedEventIds"})
    @Query("SELECT i FROM SecurityIncident i WHERE i.status IN ('NEW', 'INVESTIGATING', 'CONFIRMED', 'CONTAINED', 'RECOVERING')")
    List<SecurityIncident> findActiveIncidentsWithTags();
}