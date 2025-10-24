package io.contexa.contexacommon.repository;

import io.contexa.contexacommon.entity.AuditLog;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.List;

public interface AuditLogRepository extends JpaRepository<AuditLog, Long> {
    /**
     * [신규 추가] 특정 사용자의 최근 감사 로그 5개를 조회합니다.
     */
    List<AuditLog> findTop5ByPrincipalNameOrderByIdDesc(String principalName);

    /**
     * 위험 평가를 위한 실무급 쿼리 메서드들
     */

    // 리소스별 접근 횟수 분석
    @Query("SELECT COUNT(a) FROM AuditLog a WHERE a.resourceIdentifier = :resourceId")
    long countByResourceIdentifier(@Param("resourceId") String resourceId);

    // 리소스에 접근한 고유 사용자 수
    @Query("SELECT COUNT(DISTINCT a.principalName) FROM AuditLog a WHERE a.resourceIdentifier = :resourceId")
    long countDistinctUsersByResourceIdentifier(@Param("resourceId") String resourceId);

    // 특정 시점 이후 실패한 접근 시도 횟수
    @Query("SELECT COUNT(a) FROM AuditLog a WHERE a.resourceIdentifier = :resourceId AND a.decision = 'DENY' AND a.timestamp >= :since")
    long countFailedAttemptsSince(@Param("resourceId") String resourceId, @Param("since") LocalDateTime since);

    // IP별 접근 횟수 분석
    @Query("SELECT COUNT(a) FROM AuditLog a WHERE a.clientIp = :remoteIp")
    long countByRemoteIp(@Param("remoteIp") String remoteIp);

    // 사용자가 접근한 고유 리소스 수
    @Query("SELECT COUNT(DISTINCT a.resourceIdentifier) FROM AuditLog a WHERE a.principalName = :userId")
    long countDistinctResourcesByPrincipalName(@Param("userId") String userId);

    // 사용자의 평균 세션 지속 시간 계산을 위한 로그 조회
    @Query("SELECT a FROM AuditLog a WHERE a.principalName = :userId ORDER BY a.timestamp DESC")
    List<AuditLog> findRecentLogsByPrincipalName(@Param("userId") String userId);

    // 보안 알람을 위한 최근 DENY 로그 조회
    @Query("SELECT COUNT(a) FROM AuditLog a WHERE a.decision = 'DENY' AND a.timestamp >= :since")
    long countDeniedAttemptsSince(@Param("since") LocalDateTime since);

    // IP 평판 분석을 위한 데이터
    @Query("SELECT a FROM AuditLog a WHERE a.clientIp = :remoteIp ORDER BY a.timestamp DESC")
    List<AuditLog> findRecentLogsByClientIp(@Param("remoteIp") String remoteIp);

    // 사용자의 일반적인 접근 시간대 분석
    @Query("SELECT HOUR(a.timestamp) as hour, COUNT(a) as count FROM AuditLog a WHERE a.principalName = :userId GROUP BY HOUR(a.timestamp) ORDER BY count DESC")
    List<Object[]> findTypicalAccessHoursByPrincipalName(@Param("userId") String userId);

    /**
     * 사용자의 최근 활동 기록 조회 (최근 N일)
     */
    @Query("SELECT a FROM AuditLog a WHERE a.principalName = :userId " +
            "AND a.timestamp >= :since ORDER BY a.timestamp DESC")
    List<AuditLog> findRecentActivitiesByUserId(@Param("userId") String userId,
                                                @Param("since") LocalDateTime since);

    /**
     * 사용자의 최근 활동 기록 조회 (최근 N일)
     * BehavioralAnalysisContextRetriever에서 사용하는 메서드
     */
    default List<AuditLog> findRecentActivitiesByUserId(String userId, int days) {
        LocalDateTime since = LocalDateTime.now().minusDays(days);
        return findRecentActivitiesByUserId(userId, since);
    }

    /**
     * 사용자의 최근 실패한 시도들 조회
     */
    @Query("SELECT a FROM AuditLog a WHERE a.principalName = :userId " +
            "AND a.outcome = 'FAILURE' " +
            "AND a.timestamp >= :since " +
            "ORDER BY a.timestamp DESC")
    List<AuditLog> findRecentFailedAttemptsByUser(@Param("userId") String userId,
                                                  @Param("since") LocalDateTime since);

    /**
     * 사용자의 업무시간 외 접근 기록 조회
     * 업무시간: 평일 09:00 ~ 18:00
     */
    @Query(value = """
    SELECT *
      FROM audit_log a
     WHERE a.principal_name = :userId
       AND a.timestamp      >= :since
       AND (EXTRACT(hour  FROM a.timestamp) <  9
            OR EXTRACT(hour FROM a.timestamp) >= 18
            OR EXTRACT(isodow FROM a.timestamp) IN (6, 7))  -- 6=토, 7=일
     ORDER BY a.timestamp DESC
    """, nativeQuery = true)
    List<AuditLog> findAfterHoursAccessByUser(@Param("userId") String userId,
                                              @Param("since") LocalDateTime since);

    /**
     * 특정 기간 동안 특정 사용자의 활동 수 카운트
     */
    @Query("SELECT COUNT(a) FROM AuditLog a WHERE a.principalName = :userId " +
            "AND a.timestamp BETWEEN :startTime AND :endTime")
    long countByPrincipalNameAndTimeRange(@Param("userId") String userId,
                                          @Param("startTime") LocalDateTime startTime,
                                          @Param("endTime") LocalDateTime endTime);

    /**
     * 특정 날짜 범위의 로그 조회
     */
    List<AuditLog> findByTimestampBetween(LocalDateTime start, LocalDateTime end);

    /**
     * 특정 사용자의 특정 액션 타입 로그 조회
     */
    @Query("SELECT a FROM AuditLog a WHERE a.principalName = :userId " +
            "AND a.action LIKE %:actionType% " +
            "AND a.timestamp >= :since")
    List<AuditLog> findByUserIdAndActionType(@Param("userId") String userId,
                                             @Param("actionType") String actionType,
                                             @Param("since") LocalDateTime since);

    /**
     * 특정 사용자의 특정 아이피 로그 조회
     */
    @Query("SELECT a FROM AuditLog a WHERE a.principalName = :userId " +
            "AND a.clientIp = :ipAddress")
    List<AuditLog> findByUserIdAndClientIp(@Param("userId") String userId, @Param("ipAddress") String ipAddress);

    /**
     * IP 주소별 접근 통계
     */
    @Query("SELECT a.clientIp, COUNT(a) FROM AuditLog a " +
            "WHERE a.principalName = :userId " +
            "AND a.timestamp >= :since " +
            "GROUP BY a.clientIp")
    List<Object[]> findIpStatisticsByUser(@Param("userId") String userId,
                                          @Param("since") LocalDateTime since);

    /**
     * 특정 리소스에 대한 접근 로그
     */
    @Query("SELECT a FROM AuditLog a WHERE a.principalName = :userId " +
            "AND a.resourceUri LIKE %:resource% " +
            "AND a.timestamp >= :since")
    List<AuditLog> findByUserIdAndResource(@Param("userId") String userId,
                                           @Param("resource") String resource,
                                           @Param("since") LocalDateTime since);

    /**
     * 특정 시점 이후의 모든 로그 조회 (패턴 학습용)
     */
    @Query("SELECT a FROM AuditLog a WHERE a.timestamp >= :since ORDER BY a.timestamp DESC")
    List<AuditLog> findByCreatedAtAfter(@Param("since") LocalDateTime since);

    /**
     * 특정 사용자의 특정 시점 이후 로그 조회 (패턴 학습용)
     */
    @Query("SELECT a FROM AuditLog a WHERE a.principalName = :userId " +
            "AND a.timestamp >= :since ORDER BY a.timestamp DESC")
    List<AuditLog> findByPrincipalNameAndCreatedAtAfter(@Param("userId") String userId,
                                                        @Param("since") LocalDateTime since);
}