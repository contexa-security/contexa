package io.contexa.contexacore.repository;

import io.contexa.contexacore.domain.entity.SimulationResult;
import io.contexa.contexacore.simulation.event.SimulationProcessingCompleteEvent.SimulationMode;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

/**
 * 시뮬레이션 결과 Repository
 *
 * 시뮬레이션 결과 데이터 접근을 위한 JPA Repository입니다.
 *
 * @author contexa
 * @since 1.0.0
 */
@Repository
public interface SimulationResultRepository extends JpaRepository<SimulationResult, String> {

    /**
     * 공격 ID로 결과 조회
     *
     * @param attackId 공격 ID
     * @return 시뮬레이션 결과 목록
     */
    List<SimulationResult> findByAttackId(String attackId);

    /**
     * 공격 ID와 시뮬레이션 모드로 결과 조회
     *
     * @param attackId 공격 ID
     * @param mode 시뮬레이션 모드
     * @return 시뮬레이션 결과
     */
    Optional<SimulationResult> findByAttackIdAndSimulationMode(String attackId, SimulationMode mode);

    /**
     * 캠페인 ID로 결과 조회
     *
     * @param campaignId 캠페인 ID
     * @return 시뮬레이션 결과 목록
     */
    List<SimulationResult> findByCampaignId(String campaignId);

    /**
     * 세션 ID로 결과 조회
     *
     * @param sessionId 세션 ID
     * @return 시뮬레이션 결과 목록
     */
    List<SimulationResult> findBySessionId(String sessionId);

    /**
     * 특정 기간 내 결과 조회
     *
     * @param startTime 시작 시간
     * @param endTime 종료 시간
     * @return 시뮬레이션 결과 목록
     */
    List<SimulationResult> findByProcessedAtBetween(LocalDateTime startTime, LocalDateTime endTime);

    /**
     * 공격 타입별 탐지율 통계
     *
     * @param attackType 공격 타입
     * @param mode 시뮬레이션 모드
     * @return 탐지율 (0.0 ~ 1.0)
     */
    @Query("SELECT COALESCE(AVG(CASE WHEN s.detected = true THEN 1.0 ELSE 0.0 END), 0.0) " +
           "FROM SimulationResult s " +
           "WHERE s.attackType = :attackType " +
           "AND s.simulationMode = :mode")
    double getDetectionRateByAttackType(@Param("attackType") String attackType,
                                        @Param("mode") SimulationMode mode);

    /**
     * 공격 타입별 차단율 통계
     *
     * @param attackType 공격 타입
     * @param mode 시뮬레이션 모드
     * @return 차단율 (0.0 ~ 1.0)
     */
    @Query("SELECT COALESCE(AVG(CASE WHEN s.blocked = true THEN 1.0 ELSE 0.0 END), 0.0) " +
           "FROM SimulationResult s " +
           "WHERE s.attackType = :attackType " +
           "AND s.simulationMode = :mode")
    double getBlockingRateByAttackType(@Param("attackType") String attackType,
                                       @Param("mode") SimulationMode mode);

    /**
     * 평균 처리 시간 조회
     *
     * @param attackType 공격 타입
     * @param mode 시뮬레이션 모드
     * @return 평균 처리 시간 (밀리초)
     */
    @Query("SELECT COALESCE(AVG(s.processingTimeMs), 0) " +
           "FROM SimulationResult s " +
           "WHERE s.attackType = :attackType " +
           "AND s.simulationMode = :mode")
    double getAverageProcessingTime(@Param("attackType") String attackType,
                                    @Param("mode") SimulationMode mode);

    /**
     * 최근 결과 조회 (처리 시간 역순)
     *
     * @param limit 조회 개수
     * @return 시뮬레이션 결과 목록
     */
    @Query(value = "SELECT s FROM SimulationResult s ORDER BY s.processedAt DESC LIMIT :limit",
           nativeQuery = false)
    List<SimulationResult> findRecentResults(@Param("limit") int limit);

    /**
     * 무방비 vs 방어 비교 데이터 조회
     *
     * @param attackIds 공격 ID 목록
     * @return 시뮬레이션 결과 목록
     */
    @Query("SELECT s FROM SimulationResult s " +
           "WHERE s.attackId IN :attackIds " +
           "ORDER BY s.attackId, s.simulationMode")
    List<SimulationResult> findComparisonResults(@Param("attackIds") List<String> attackIds);

    /**
     * 처리 실패한 결과 조회
     *
     * @return 실패한 시뮬레이션 결과 목록
     */
    List<SimulationResult> findByProcessingSuccessFalse();

    /**
     * 이벤트 ID 존재 여부 확인
     *
     * @param eventId 이벤트 ID
     * @return 존재 여부
     */
    boolean existsByEventId(String eventId);
}