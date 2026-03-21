package io.contexa.contexacommon.repository;

import io.contexa.contexacommon.entity.AuditLog;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.List;

public interface AuditLogRepository extends JpaRepository<AuditLog, Long> {
    
    List<AuditLog> findTop5ByPrincipalNameOrderByIdDesc(String principalName);

    @Query("SELECT COUNT(a) FROM AuditLog a WHERE a.resourceIdentifier = :resourceId")
    long countByResourceIdentifier(@Param("resourceId") String resourceId);

    
    @Query("SELECT COUNT(DISTINCT a.principalName) FROM AuditLog a WHERE a.resourceIdentifier = :resourceId")
    long countDistinctUsersByResourceIdentifier(@Param("resourceId") String resourceId);

    
    @Query("SELECT COUNT(a) FROM AuditLog a WHERE a.resourceIdentifier = :resourceId AND a.decision = 'DENY' AND a.timestamp >= :since")
    long countFailedAttemptsSince(@Param("resourceId") String resourceId, @Param("since") LocalDateTime since);

    
    @Query("SELECT COUNT(a) FROM AuditLog a WHERE a.clientIp = :remoteIp")
    long countByRemoteIp(@Param("remoteIp") String remoteIp);

    
    @Query("SELECT COUNT(DISTINCT a.resourceIdentifier) FROM AuditLog a WHERE a.principalName = :userId")
    long countDistinctResourcesByPrincipalName(@Param("userId") String userId);

    
    @Query("SELECT a FROM AuditLog a WHERE a.principalName = :userId ORDER BY a.timestamp DESC")
    List<AuditLog> findRecentLogsByPrincipalName(@Param("userId") String userId);

    
    @Query("SELECT COUNT(a) FROM AuditLog a WHERE a.decision = 'DENY' AND a.timestamp >= :since")
    long countDeniedAttemptsSince(@Param("since") LocalDateTime since);

    
    @Query("SELECT a FROM AuditLog a WHERE a.clientIp = :remoteIp ORDER BY a.timestamp DESC")
    List<AuditLog> findRecentLogsByClientIp(@Param("remoteIp") String remoteIp);

    
    @Query("SELECT HOUR(a.timestamp) as hour, COUNT(a) as count FROM AuditLog a WHERE a.principalName = :userId GROUP BY HOUR(a.timestamp) ORDER BY count DESC")
    List<Object[]> findTypicalAccessHoursByPrincipalName(@Param("userId") String userId);

    
    @Query("SELECT a FROM AuditLog a WHERE a.principalName = :userId " +
            "AND a.timestamp >= :since ORDER BY a.timestamp DESC")
    List<AuditLog> findRecentActivitiesByUserId(@Param("userId") String userId,
                                                @Param("since") LocalDateTime since);

    
    default List<AuditLog> findRecentActivitiesByUserId(String userId, int days) {
        LocalDateTime since = LocalDateTime.now().minusDays(days);
        return findRecentActivitiesByUserId(userId, since);
    }

    @Query("SELECT a FROM AuditLog a WHERE a.principalName = :userId " +
            "AND a.outcome = 'FAILURE' " +
            "AND a.timestamp >= :since " +
            "ORDER BY a.timestamp DESC")
    List<AuditLog> findRecentFailedAttemptsByUser(@Param("userId") String userId,
                                                  @Param("since") LocalDateTime since);

    @Query(value = """
    SELECT *
      FROM audit_log a
     WHERE a.principal_name = :userId
       AND a.timestamp      >= :since
       AND (EXTRACT(hour  FROM a.timestamp) <  9
            OR EXTRACT(hour FROM a.timestamp) >= 18
            OR EXTRACT(isodow FROM a.timestamp) IN (6, 7))  -- 6=Sat, 7=Sun
     ORDER BY a.timestamp DESC
    """, nativeQuery = true)
    List<AuditLog> findAfterHoursAccessByUser(@Param("userId") String userId,
                                              @Param("since") LocalDateTime since);

    
    @Query("SELECT COUNT(a) FROM AuditLog a WHERE a.principalName = :userId " +
            "AND a.timestamp BETWEEN :startTime AND :endTime")
    long countByPrincipalNameAndTimeRange(@Param("userId") String userId,
                                          @Param("startTime") LocalDateTime startTime,
                                          @Param("endTime") LocalDateTime endTime);

    
    List<AuditLog> findByTimestampBetween(LocalDateTime start, LocalDateTime end);

    
    @Query("SELECT a FROM AuditLog a WHERE a.principalName = :userId " +
            "AND a.action LIKE %:actionType% " +
            "AND a.timestamp >= :since")
    List<AuditLog> findByUserIdAndActionType(@Param("userId") String userId,
                                             @Param("actionType") String actionType,
                                             @Param("since") LocalDateTime since);

    
    @Query("SELECT a FROM AuditLog a WHERE a.principalName = :userId " +
            "AND a.clientIp = :ipAddress")
    List<AuditLog> findByUserIdAndClientIp(@Param("userId") String userId, @Param("ipAddress") String ipAddress);

    
    @Query("SELECT a.clientIp, COUNT(a) FROM AuditLog a " +
            "WHERE a.principalName = :userId " +
            "AND a.timestamp >= :since " +
            "GROUP BY a.clientIp")
    List<Object[]> findIpStatisticsByUser(@Param("userId") String userId,
                                          @Param("since") LocalDateTime since);

    
    @Query("SELECT a FROM AuditLog a WHERE a.principalName = :userId " +
            "AND a.resourceUri LIKE %:resource% " +
            "AND a.timestamp >= :since")
    List<AuditLog> findByUserIdAndResource(@Param("userId") String userId,
                                           @Param("resource") String resource,
                                           @Param("since") LocalDateTime since);

    
    @Query("SELECT a FROM AuditLog a WHERE a.timestamp >= :since ORDER BY a.timestamp DESC")
    List<AuditLog> findByCreatedAtAfter(@Param("since") LocalDateTime since);

    
    @Query("SELECT a FROM AuditLog a WHERE a.principalName = :userId " +
            "AND a.timestamp >= :since ORDER BY a.timestamp DESC")
    List<AuditLog> findByPrincipalNameAndCreatedAtAfter(@Param("userId") String userId,
                                                        @Param("since") LocalDateTime since);

    // Dashboard aggregate queries
    @Query("SELECT COUNT(a) FROM AuditLog a WHERE a.decision = 'ALLOW' AND a.timestamp >= :since")
    long countAllowedSince(@Param("since") LocalDateTime since);

    @Query("SELECT COUNT(a) FROM AuditLog a WHERE a.eventCategory = :category AND a.timestamp >= :since")
    long countByEventCategoryAndTimestampAfter(@Param("category") String category, @Param("since") LocalDateTime since);

    @Query("SELECT COUNT(a) FROM AuditLog a WHERE a.eventCategory = 'ADMIN_OVERRIDE' AND a.timestamp >= :since")
    long countAdminOverridesSince(@Param("since") LocalDateTime since);

    @Query("SELECT COUNT(a) FROM AuditLog a WHERE a.eventCategory = 'SECURITY_ERROR' AND a.timestamp >= :since")
    long countSecurityErrorsSince(@Param("since") LocalDateTime since);

    @Query("SELECT AVG(a.riskScore) FROM AuditLog a WHERE a.riskScore IS NOT NULL AND a.timestamp >= :since")
    Double avgRiskScoreSince(@Param("since") LocalDateTime since);

    @Query(value = "SELECT COUNT(*) FROM audit_log WHERE timestamp >= :since " +
            "AND (EXTRACT(hour FROM timestamp) < 9 OR EXTRACT(hour FROM timestamp) >= 18 " +
            "OR EXTRACT(isodow FROM timestamp) IN (6, 7))", nativeQuery = true)
    long countAfterHoursAccessSince(@Param("since") LocalDateTime since);

    @Query("SELECT COUNT(DISTINCT a.clientIp) FROM AuditLog a WHERE a.timestamp >= :since")
    long countDistinctIpsSince(@Param("since") LocalDateTime since);
}