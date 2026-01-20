package io.contexa.contexacore.repository;

import io.contexa.contexacore.domain.entity.AttackResult;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;


@Repository
public interface AttackResultRepository extends JpaRepository<AttackResult, String> {

    
    List<AttackResult> findByCampaignId(String campaignId);

    
    List<AttackResult> findByCampaignIdAndAttackType(String campaignId, AttackResult.AttackType attackType);

    
    List<AttackResult> findByCampaignIdAndAttackSuccessful(String campaignId, boolean successful);

    
    List<AttackResult> findByCampaignIdAndDataBreached(String campaignId, boolean breached);

    
    @Query("SELECT DISTINCT a.campaignId FROM AttackResult a ORDER BY a.executionTime DESC")
    List<String> findDistinctCampaignIds(@Param("limit") int limit);

    
    @Query("SELECT AVG(a.riskScore) FROM AttackResult a WHERE a.campaignId = :campaignId")
    Double calculateAverageRiskScore(@Param("campaignId") String campaignId);

    
    @Query("SELECT COUNT(a) * 100.0 / (SELECT COUNT(a2) FROM AttackResult a2 WHERE a2.campaignId = :campaignId) " +
           "FROM AttackResult a WHERE a.campaignId = :campaignId AND a.attackSuccessful = true")
    Double calculateSuccessRate(@Param("campaignId") String campaignId);
}