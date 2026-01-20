package io.contexa.contexacore.repository;

import io.contexa.contexacore.domain.entity.ThreatIndicator;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;


@Repository
public interface ThreatIndicatorRepository extends JpaRepository<ThreatIndicator, String> {
    
    
    List<ThreatIndicator> findByType(ThreatIndicator.IndicatorType type);
    
    
    List<ThreatIndicator> findBySeverity(ThreatIndicator.Severity severity);
    
    
    @Query("SELECT i FROM ThreatIndicator i WHERE i.active = true")
    List<ThreatIndicator> findActiveIndicators();
    
    
    @Query("SELECT i FROM ThreatIndicator i WHERE i.active = true AND i.severity IN ('HIGH', 'CRITICAL')")
    List<ThreatIndicator> findHighRiskActiveIndicators();
    
    
    @Query("SELECT i FROM ThreatIndicator i WHERE i.mitreAttackId = :mitreId")
    List<ThreatIndicator> findByMitreAttackId(@Param("mitreId") String mitreId);
    
    
    @Query("SELECT i FROM ThreatIndicator i WHERE i.nistCsfCategory = :category")
    List<ThreatIndicator> findByNistCsfCategory(@Param("category") String category);
    
    
    @Query("SELECT i FROM ThreatIndicator i WHERE i.cisControl = :control")
    List<ThreatIndicator> findByCisControl(@Param("control") String control);
    
    
    List<ThreatIndicator> findBySource(String source);
    
    
    @Query("SELECT i FROM ThreatIndicator i WHERE i.detectedAt BETWEEN :startDate AND :endDate")
    List<ThreatIndicator> findIndicatorsByDateRange(
        @Param("startDate") LocalDateTime startDate,
        @Param("endDate") LocalDateTime endDate
    );
    
    
    @Query("SELECT i FROM ThreatIndicator i WHERE i.confidence >= :minConfidence")
    List<ThreatIndicator> findByMinimumConfidence(@Param("minConfidence") double minConfidence);
    
    
    @Query("SELECT i FROM ThreatIndicator i WHERE i.value = :iocValue")
    List<ThreatIndicator> findByIoCValue(@Param("iocValue") String iocValue);
    
    
    @Query("SELECT i FROM ThreatIndicator i WHERE i.type = 'IP_ADDRESS' AND i.value = :ipAddress")
    List<ThreatIndicator> findByIpAddress(@Param("ipAddress") String ipAddress);
    
    
    @Query("SELECT i FROM ThreatIndicator i WHERE i.type = 'DOMAIN' AND (i.value = :domain OR i.value LIKE CONCAT('%.', :domain))")
    List<ThreatIndicator> findByDomain(@Param("domain") String domain);
    
    
    @Query("SELECT i FROM ThreatIndicator i WHERE i.type = :hashType AND i.value = :hashValue")
    List<ThreatIndicator> findByHash(
        @Param("hashValue") String hashValue,
        @Param("hashType") ThreatIndicator.IndicatorType hashType
    );
    
    
    @Query("SELECT i FROM ThreatIndicator i JOIN i.incidents inc WHERE inc.incidentId = :incidentId")
    List<ThreatIndicator> findByIncidentId(@Param("incidentId") String incidentId);
    
    
    @Query("SELECT i FROM ThreatIndicator i JOIN i.tags t WHERE t = :tag")
    List<ThreatIndicator> findByTag(@Param("tag") String tag);
    
    
    @Modifying
    @Transactional
    @Query("UPDATE ThreatIndicator i SET i.active = false WHERE i.expiresAt < :expirationDate AND i.active = true")
    int deactivateExpiredIndicators(@Param("expirationDate") LocalDateTime expirationDate);
    
    
    @Modifying
    @Query("UPDATE ThreatIndicator i SET i.confidence = :confidence, i.updatedAt = CURRENT_TIMESTAMP WHERE i.indicatorId = :indicatorId")
    int updateIndicatorConfidence(
        @Param("indicatorId") String indicatorId,
        @Param("confidence") double confidence
    );
    
    
    @Modifying
    @Query("UPDATE ThreatIndicator i SET i.severity = :severity, i.updatedAt = CURRENT_TIMESTAMP WHERE i.indicatorId = :indicatorId")
    int updateIndicatorSeverity(
        @Param("indicatorId") String indicatorId,
        @Param("severity") ThreatIndicator.Severity severity
    );
    
    
    @Query("SELECT i.type, COUNT(i) FROM ThreatIndicator i WHERE i.active = true GROUP BY i.type")
    List<Object[]> getIndicatorStatistics();
    
    
    @Query("SELECT " +
           "COUNT(CASE WHEN i.mitreAttackId IS NOT NULL THEN 1 END) as mitreCount, " +
           "COUNT(CASE WHEN i.nistCsfCategory IS NOT NULL THEN 1 END) as nistCount, " +
           "COUNT(CASE WHEN i.cisControl IS NOT NULL THEN 1 END) as cisCount " +
           "FROM ThreatIndicator i WHERE i.active = true")
    Map<String, Long> getFrameworkMappingStatistics();
    
    
    @Query("SELECT i FROM ThreatIndicator i WHERE i.active = true ORDER BY i.detectedAt DESC")
    List<ThreatIndicator> findRecentIndicators(Pageable pageable);
    
    
    @Query("SELECT i FROM ThreatIndicator i WHERE i.active = true AND i.threatScore >= :minScore ORDER BY i.threatScore DESC")
    List<ThreatIndicator> findHighThreatIndicators(
        @Param("minScore") double minScore,
        Pageable pageable
    );
    
    
    @Query("SELECT COUNT(i) > 0 FROM ThreatIndicator i WHERE i.type = :type AND i.value = :value AND i.active = true")
    boolean existsActiveIndicator(
        @Param("type") ThreatIndicator.IndicatorType type,
        @Param("value") String value
    );
    
    
    @Query("SELECT DISTINCT i2 FROM ThreatIndicator i1 " +
           "JOIN i1.relatedIndicators i2 " +
           "WHERE i1.indicatorId = :indicatorId AND i2.active = true")
    List<ThreatIndicator> findRelatedIndicators(@Param("indicatorId") String indicatorId);
    
    
    @Query("SELECT i FROM ThreatIndicator i WHERE i.campaignId = :campaignId")
    List<ThreatIndicator> findByCampaignId(@Param("campaignId") String campaignId);
    
    
    @Query("SELECT i FROM ThreatIndicator i WHERE i.threatActorId = :actorId")
    List<ThreatIndicator> findByThreatActorId(@Param("actorId") String actorId);
}