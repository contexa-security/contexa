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

/**
 * 위협 지표 리포지토리
 * 
 * JPA를 사용한 위협 지표 데이터 접근 계층입니다.
 * MITRE ATT&CK, NIST CSF, CIS Controls 프레임워크 매핑을 지원합니다.
 */
@Repository
public interface ThreatIndicatorRepository extends JpaRepository<ThreatIndicator, String> {
    
    /**
     * 타입별 위협 지표 조회
     * 
     * @param type 지표 타입
     * @return 해당 타입의 지표 리스트
     */
    List<ThreatIndicator> findByType(ThreatIndicator.IndicatorType type);
    
    /**
     * 심각도별 위협 지표 조회
     * 
     * @param severity 심각도
     * @return 해당 심각도의 지표 리스트
     */
    List<ThreatIndicator> findBySeverity(ThreatIndicator.Severity severity);
    
    /**
     * 활성 위협 지표 조회
     * 
     * @return 활성 상태의 지표 리스트
     */
    @Query("SELECT i FROM ThreatIndicator i WHERE i.active = true")
    List<ThreatIndicator> findActiveIndicators();
    
    /**
     * 고위험 활성 지표 조회
     * 
     * @return 고위험 활성 지표 리스트
     */
    @Query("SELECT i FROM ThreatIndicator i WHERE i.active = true AND i.severity IN ('HIGH', 'CRITICAL')")
    List<ThreatIndicator> findHighRiskActiveIndicators();
    
    /**
     * MITRE ATT&CK ID로 지표 조회
     * 
     * @param mitreId MITRE ATT&CK ID
     * @return 해당 MITRE ID의 지표 리스트
     */
    @Query("SELECT i FROM ThreatIndicator i WHERE i.mitreAttackId = :mitreId")
    List<ThreatIndicator> findByMitreAttackId(@Param("mitreId") String mitreId);
    
    /**
     * NIST CSF 카테고리별 지표 조회
     * 
     * @param category NIST CSF 카테고리
     * @return 해당 카테고리의 지표 리스트
     */
    @Query("SELECT i FROM ThreatIndicator i WHERE i.nistCsfCategory = :category")
    List<ThreatIndicator> findByNistCsfCategory(@Param("category") String category);
    
    /**
     * CIS Controls별 지표 조회
     * 
     * @param control CIS Control
     * @return 해당 Control의 지표 리스트
     */
    @Query("SELECT i FROM ThreatIndicator i WHERE i.cisControl = :control")
    List<ThreatIndicator> findByCisControl(@Param("control") String control);
    
    /**
     * 소스별 지표 조회
     * 
     * @param source 지표 소스
     * @return 해당 소스의 지표 리스트
     */
    List<ThreatIndicator> findBySource(String source);
    
    /**
     * 기간별 지표 조회
     * 
     * @param startDate 시작 날짜
     * @param endDate 종료 날짜
     * @return 해당 기간의 지표 리스트
     */
    @Query("SELECT i FROM ThreatIndicator i WHERE i.detectedAt BETWEEN :startDate AND :endDate")
    List<ThreatIndicator> findIndicatorsByDateRange(
        @Param("startDate") LocalDateTime startDate,
        @Param("endDate") LocalDateTime endDate
    );
    
    /**
     * 신뢰도별 지표 조회
     * 
     * @param minConfidence 최소 신뢰도
     * @return 신뢰도가 기준 이상인 지표 리스트
     */
    @Query("SELECT i FROM ThreatIndicator i WHERE i.confidence >= :minConfidence")
    List<ThreatIndicator> findByMinimumConfidence(@Param("minConfidence") double minConfidence);
    
    /**
     * IoC 값으로 지표 검색
     * 
     * @param iocValue IoC 값
     * @return 매칭되는 지표 리스트
     */
    @Query("SELECT i FROM ThreatIndicator i WHERE i.value = :iocValue")
    List<ThreatIndicator> findByIoCValue(@Param("iocValue") String iocValue);
    
    /**
     * IP 주소 관련 지표 조회
     * 
     * @param ipAddress IP 주소
     * @return IP 관련 지표 리스트
     */
    @Query("SELECT i FROM ThreatIndicator i WHERE i.type = 'IP_ADDRESS' AND i.value = :ipAddress")
    List<ThreatIndicator> findByIpAddress(@Param("ipAddress") String ipAddress);
    
    /**
     * 도메인 관련 지표 조회
     * 
     * @param domain 도메인
     * @return 도메인 관련 지표 리스트
     */
    @Query("SELECT i FROM ThreatIndicator i WHERE i.type = 'DOMAIN' AND (i.value = :domain OR i.value LIKE CONCAT('%.', :domain))")
    List<ThreatIndicator> findByDomain(@Param("domain") String domain);
    
    /**
     * 해시값으로 지표 조회
     * 
     * @param hashValue 해시값
     * @param hashType 해시 타입 (MD5, SHA256 등)
     * @return 해시 관련 지표 리스트
     */
    @Query("SELECT i FROM ThreatIndicator i WHERE i.type = :hashType AND i.value = :hashValue")
    List<ThreatIndicator> findByHash(
        @Param("hashValue") String hashValue,
        @Param("hashType") ThreatIndicator.IndicatorType hashType
    );
    
    /**
     * 관련 인시던트가 있는 지표 조회
     * 
     * @param incidentId 인시던트 ID
     * @return 인시던트와 관련된 지표 리스트
     */
    @Query("SELECT i FROM ThreatIndicator i JOIN i.incidents inc WHERE inc.incidentId = :incidentId")
    List<ThreatIndicator> findByIncidentId(@Param("incidentId") String incidentId);
    
    /**
     * 태그별 지표 조회
     * 
     * @param tag 태그
     * @return 해당 태그를 가진 지표 리스트
     */
    @Query("SELECT i FROM ThreatIndicator i JOIN i.tags t WHERE t = :tag")
    List<ThreatIndicator> findByTag(@Param("tag") String tag);
    
    /**
     * 만료된 지표 비활성화
     * 
     * @param expirationDate 만료 기준 날짜
     * @return 비활성화된 지표 수
     */
    @Modifying
    @Transactional
    @Query("UPDATE ThreatIndicator i SET i.active = false WHERE i.expiresAt < :expirationDate AND i.active = true")
    int deactivateExpiredIndicators(@Param("expirationDate") LocalDateTime expirationDate);
    
    /**
     * 지표 신뢰도 업데이트
     * 
     * @param indicatorId 지표 ID
     * @param confidence 새로운 신뢰도
     * @return 업데이트 성공 여부
     */
    @Modifying
    @Query("UPDATE ThreatIndicator i SET i.confidence = :confidence, i.updatedAt = CURRENT_TIMESTAMP WHERE i.indicatorId = :indicatorId")
    int updateIndicatorConfidence(
        @Param("indicatorId") String indicatorId,
        @Param("confidence") double confidence
    );
    
    /**
     * 지표 심각도 업데이트
     * 
     * @param indicatorId 지표 ID
     * @param severity 새로운 심각도
     * @return 업데이트 성공 여부
     */
    @Modifying
    @Query("UPDATE ThreatIndicator i SET i.severity = :severity, i.updatedAt = CURRENT_TIMESTAMP WHERE i.indicatorId = :indicatorId")
    int updateIndicatorSeverity(
        @Param("indicatorId") String indicatorId,
        @Param("severity") ThreatIndicator.Severity severity
    );
    
    /**
     * 지표 통계 조회
     * 
     * @return 타입별 지표 수
     */
    @Query("SELECT i.type, COUNT(i) FROM ThreatIndicator i WHERE i.active = true GROUP BY i.type")
    List<Object[]> getIndicatorStatistics();
    
    /**
     * 프레임워크별 매핑 통계
     * 
     * @return 프레임워크별 매핑 수
     */
    @Query("SELECT " +
           "COUNT(CASE WHEN i.mitreAttackId IS NOT NULL THEN 1 END) as mitreCount, " +
           "COUNT(CASE WHEN i.nistCsfCategory IS NOT NULL THEN 1 END) as nistCount, " +
           "COUNT(CASE WHEN i.cisControl IS NOT NULL THEN 1 END) as cisCount " +
           "FROM ThreatIndicator i WHERE i.active = true")
    Map<String, Long> getFrameworkMappingStatistics();
    
    /**
     * 최근 탐지된 지표 조회
     * 
     * @param pageable 페이지 정보
     * @return 최근 탐지된 지표 리스트
     */
    @Query("SELECT i FROM ThreatIndicator i WHERE i.active = true ORDER BY i.detectedAt DESC")
    List<ThreatIndicator> findRecentIndicators(Pageable pageable);
    
    /**
     * 위협 점수가 높은 지표 조회
     * 
     * @param minScore 최소 위협 점수
     * @param pageable 페이지 정보
     * @return 위협 점수가 높은 지표 리스트
     */
    @Query("SELECT i FROM ThreatIndicator i WHERE i.active = true AND i.threatScore >= :minScore ORDER BY i.threatScore DESC")
    List<ThreatIndicator> findHighThreatIndicators(
        @Param("minScore") double minScore,
        Pageable pageable
    );
    
    /**
     * 중복 지표 확인
     * 
     * @param type 지표 타입
     * @param value 지표 값
     * @return 중복 존재 여부
     */
    @Query("SELECT COUNT(i) > 0 FROM ThreatIndicator i WHERE i.type = :type AND i.value = :value AND i.active = true")
    boolean existsActiveIndicator(
        @Param("type") ThreatIndicator.IndicatorType type,
        @Param("value") String value
    );
    
    /**
     * 연관 지표 조회
     * 
     * @param indicatorId 기준 지표 ID
     * @return 연관된 지표 리스트
     */
    @Query("SELECT DISTINCT i2 FROM ThreatIndicator i1 " +
           "JOIN i1.relatedIndicators i2 " +
           "WHERE i1.indicatorId = :indicatorId AND i2.active = true")
    List<ThreatIndicator> findRelatedIndicators(@Param("indicatorId") String indicatorId);
    
    /**
     * 캠페인별 지표 조회
     * 
     * @param campaignId 캠페인 ID
     * @return 캠페인과 관련된 지표 리스트
     */
    @Query("SELECT i FROM ThreatIndicator i WHERE i.campaignId = :campaignId")
    List<ThreatIndicator> findByCampaignId(@Param("campaignId") String campaignId);
    
    /**
     * 위협 액터별 지표 조회
     * 
     * @param actorId 위협 액터 ID
     * @return 액터와 관련된 지표 리스트
     */
    @Query("SELECT i FROM ThreatIndicator i WHERE i.threatActorId = :actorId")
    List<ThreatIndicator> findByThreatActorId(@Param("actorId") String actorId);
}