package io.contexa.contexacore.repository;

import io.contexa.contexacore.domain.entity.AttackResult;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * 공격 결과 리포지토리
 *
 * @author AI3Security
 * @since 1.0.0
 */
@Repository
public interface AttackResultRepository extends JpaRepository<AttackResult, String> {

    /**
     * 캠페인 ID로 공격 결과 조회
     */
    List<AttackResult> findByCampaignId(String campaignId);

    /**
     * 캠페인 ID와 공격 타입으로 조회
     */
    List<AttackResult> findByCampaignIdAndAttackType(String campaignId, AttackResult.AttackType attackType);

    /**
     * 성공한 공격만 조회
     */
    List<AttackResult> findByCampaignIdAndAttackSuccessful(String campaignId, boolean successful);

    /**
     * 데이터 유출이 발생한 공격만 조회
     */
    List<AttackResult> findByCampaignIdAndDataBreached(String campaignId, boolean breached);

    /**
     * 최근 캠페인 ID 목록 조회
     */
    @Query("SELECT DISTINCT a.campaignId FROM AttackResult a ORDER BY a.executionTime DESC")
    List<String> findDistinctCampaignIds(@Param("limit") int limit);

    /**
     * 캠페인의 평균 위험도 계산
     */
    @Query("SELECT AVG(a.riskScore) FROM AttackResult a WHERE a.campaignId = :campaignId")
    Double calculateAverageRiskScore(@Param("campaignId") String campaignId);

    /**
     * 캠페인의 공격 성공률 계산
     */
    @Query("SELECT COUNT(a) * 100.0 / (SELECT COUNT(a2) FROM AttackResult a2 WHERE a2.campaignId = :campaignId) " +
           "FROM AttackResult a WHERE a.campaignId = :campaignId AND a.attackSuccessful = true")
    Double calculateSuccessRate(@Param("campaignId") String campaignId);
}