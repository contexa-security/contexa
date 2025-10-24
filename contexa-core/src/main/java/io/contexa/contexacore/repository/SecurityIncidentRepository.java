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

/**
 * 보안 인시던트 리포지토리
 * 
 * JPA를 사용한 보안 인시던트 데이터 접근 계층입니다.
 * Spring Data JPA의 표준 리포지토리 패턴을 따릅니다.
 */
public interface SecurityIncidentRepository extends JpaRepository<SecurityIncident, String> {
    
    /**
     * 활성 인시던트 조회
     * 
     * @return 활성 상태의 인시던트 리스트
     */
    @Query("SELECT i FROM SecurityIncident i WHERE i.status IN ('NEW', 'INVESTIGATING', 'CONFIRMED', 'CONTAINED', 'RECOVERING')")
    List<SecurityIncident> findActiveIncidents();
    
    /**
     * 조직별 활성 인시던트 조회
     * 
     * @param organizationId 조직 ID
     * @return 해당 조직의 활성 인시던트 리스트
     */
    @Query("SELECT i FROM SecurityIncident i WHERE i.organizationId = :organizationId AND i.status IN ('NEW', 'INVESTIGATING', 'CONFIRMED', 'CONTAINED', 'RECOVERING')")
    List<SecurityIncident> findActiveIncidentsByOrganization(@Param("organizationId") String organizationId);
    
    /**
     * 위협 수준별 인시던트 조회
     * 
     * @param threatLevel 위협 수준
     * @return 해당 위협 수준의 인시던트 리스트
     */
    List<SecurityIncident> findByThreatLevel(SecurityIncident.ThreatLevel threatLevel);
    
    /**
     * 고위험 활성 인시던트 조회
     * 
     * @param status 인시던트 상태
     * @return 고위험 활성 인시던트 리스트
     */
    @Query("SELECT i FROM SecurityIncident i WHERE i.status = :status AND i.threatLevel IN ('HIGH', 'CRITICAL')")
    List<SecurityIncident> findHighRiskActiveIncidents(@Param("status") SecurityIncident.IncidentStatus status);
    
    /**
     * 기간별 인시던트 조회
     * 
     * @param startDate 시작 날짜
     * @param endDate 종료 날짜
     * @return 해당 기간의 인시던트 리스트
     */
    @Query("SELECT i FROM SecurityIncident i WHERE i.createdAt BETWEEN :startDate AND :endDate")
    List<SecurityIncident> findIncidentsByDateRange(
        @Param("startDate") LocalDateTime startDate, 
        @Param("endDate") LocalDateTime endDate
    );
    
    /**
     * 사용자별 인시던트 조회
     * 
     * @param userId 사용자 ID
     * @return 해당 사용자와 관련된 인시던트 리스트
     */
    @Query("SELECT i FROM SecurityIncident i WHERE i.affectedUser = :userId")
    List<SecurityIncident> findIncidentsByUser(@Param("userId") String userId);
    
    /**
     * 자산별 인시던트 조회
     * 
     * @param assetId 자산 ID
     * @return 해당 자산과 관련된 인시던트 리스트
     */
    @Query("SELECT i FROM SecurityIncident i JOIN i.affectedAssets a WHERE a = :assetId")
    List<SecurityIncident> findIncidentsByAsset(@Param("assetId") String assetId);
    
    /**
     * 타입별 인시던트 조회
     * 
     * @param type 인시던트 타입
     * @return 해당 타입의 인시던트 리스트
     */
    List<SecurityIncident> findByType(SecurityIncident.IncidentType type);
    
    /**
     * 승인 대기 중인 인시던트 조회
     * 
     * @return 승인이 필요한 인시던트 리스트
     */
    @Query("SELECT i FROM SecurityIncident i WHERE i.requiresApproval = true AND i.status IN ('NEW', 'INVESTIGATING')")
    List<SecurityIncident> findIncidentsRequiringApproval();
    
    /**
     * 자동 대응 가능한 인시던트 조회
     * 
     * @return 자동 대응 가능한 인시던트 리스트
     */
    @Query("SELECT i FROM SecurityIncident i WHERE i.autoResponseEnabled = true AND i.requiresApproval = false AND i.status IN ('NEW', 'INVESTIGATING')")
    List<SecurityIncident> findAutoRespondableIncidents();
    
    /**
     * 만료된 인시던트 업데이트
     * 
     * @param threshold 만료 기준 시간
     * @return 업데이트된 인시던트 수
     */
    @Modifying
    @Query("UPDATE SecurityIncident i SET i.status = 'CLOSED' WHERE i.createdAt < :threshold AND i.status IN ('NEW', 'INVESTIGATING')")
    int expireOldIncidents(@Param("threshold") LocalDateTime threshold);
    
    /**
     * 에스컬레이션이 필요한 인시던트 조회
     * 
     * @param threshold 에스컬레이션 기준 시간
     * @return 에스컬레이션이 필요한 인시던트 리스트
     */
    @Query("SELECT i FROM SecurityIncident i WHERE i.createdAt < :threshold AND i.status IN ('NEW', 'INVESTIGATING') AND i.escalatedAt IS NULL")
    List<SecurityIncident> findIncidentsNeedingEscalation(@Param("threshold") LocalDateTime threshold);
    
    /**
     * 최근 인시던트 조회
     * 
     * @param pageable 페이지 정보
     * @return 최근 인시던트 리스트
     */
    @Query("SELECT i FROM SecurityIncident i ORDER BY i.createdAt DESC")
    List<SecurityIncident> findRecentIncidents(Pageable pageable);
    
    /**
     * 인시던트 통계 조회
     * 
     * @param organizationId 조직 ID
     * @return 인시던트 통계
     */
    @Query("SELECT i.threatLevel, COUNT(i) FROM SecurityIncident i WHERE i.organizationId = :organizationId GROUP BY i.threatLevel")
    List<Object[]> getIncidentStatisticsByOrganization(@Param("organizationId") String organizationId);
    
    /**
     * 중복 인시던트 확인
     * 
     * @param sourceIp 소스 IP
     * @param type 인시던트 타입
     * @param timeWindow 시간 범위
     * @return 중복 인시던트 존재 여부
     */
    @Query("SELECT COUNT(i) > 0 FROM SecurityIncident i WHERE i.sourceIp = :sourceIp AND i.type = :type AND i.createdAt > :timeWindow")
    boolean existsSimilarIncident(
        @Param("sourceIp") String sourceIp, 
        @Param("type") SecurityIncident.IncidentType type,
        @Param("timeWindow") LocalDateTime timeWindow
    );
    
    /**
     * 인시던트 상태 업데이트
     * 
     * @param incidentId 인시던트 ID
     * @param status 새로운 상태
     * @return 업데이트 성공 여부
     */
    @Modifying
    @Query("UPDATE SecurityIncident i SET i.status = :status, i.updatedAt = CURRENT_TIMESTAMP WHERE i.incidentId = :incidentId")
    int updateIncidentStatus(
        @Param("incidentId") String incidentId, 
        @Param("status") SecurityIncident.IncidentStatus status
    );
    
    /**
     * 인시던트 위협 수준 업데이트
     * 
     * @param incidentId 인시던트 ID
     * @param threatLevel 새로운 위협 수준
     * @return 업데이트 성공 여부
     */
    @Modifying
    @Query("UPDATE SecurityIncident i SET i.threatLevel = :threatLevel, i.updatedAt = CURRENT_TIMESTAMP WHERE i.incidentId = :incidentId")
    int updateIncidentThreatLevel(
        @Param("incidentId") String incidentId, 
        @Param("threatLevel") SecurityIncident.ThreatLevel threatLevel
    );
    
    /**
     * 위험 점수가 특정 임계치를 초과하고 상태가 일치하는 인시던트 조회
     * 
     * @param threshold 위험 점수 임계치
     * @param status 인시던트 상태
     * @return 해당 조건의 인시던트 리스트
     */
    @Query("SELECT i FROM SecurityIncident i WHERE i.riskScore > :threshold AND i.status = :status")
    List<SecurityIncident> findByRiskScoreGreaterThanAndStatus(
        @Param("threshold") double threshold,
        @Param("status") String status
    );
    
    /**
     * 특정 상태의 인시던트 개수 카운트
     *
     * @param status 인시던트 상태
     * @return 해당 상태의 인시던트 개수
     */
    @Query("SELECT COUNT(i) FROM SecurityIncident i WHERE i.status = :status")
    long countByStatus(@Param("status") String status);

    /**
     * 태그와 관련 이벤트를 즉시 로딩하여 인시던트 조회 (LazyInitializationException 방지)
     *
     * @param incidentId 인시던트 ID
     * @return 태그가 즉시 로딩된 인시던트
     */
    @EntityGraph(attributePaths = {"tags", "relatedEventIds"})
    Optional<SecurityIncident> findWithTagsByIncidentId(String incidentId);

    /**
     * 활성 인시던트를 태그와 함께 조회 (LazyInitializationException 방지)
     *
     * @return 태그가 즉시 로딩된 활성 인시던트 리스트
     */
    @EntityGraph(attributePaths = {"tags", "relatedEventIds"})
    @Query("SELECT i FROM SecurityIncident i WHERE i.status IN ('NEW', 'INVESTIGATING', 'CONFIRMED', 'CONTAINED', 'RECOVERING')")
    List<SecurityIncident> findActiveIncidentsWithTags();
}