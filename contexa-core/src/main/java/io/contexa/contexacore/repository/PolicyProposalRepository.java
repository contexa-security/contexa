package io.contexa.contexacore.repository;

import io.contexa.contexacore.domain.entity.PolicyEvolutionProposal;
import io.contexa.contexacore.domain.entity.PolicyEvolutionProposal.ProposalStatus;
import io.contexa.contexacore.autonomous.domain.LearningMetadata;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface PolicyProposalRepository extends JpaRepository<PolicyEvolutionProposal, Long> {

    List<PolicyEvolutionProposal> findByStatus(ProposalStatus status);

    Page<PolicyEvolutionProposal> findByStatus(ProposalStatus status, Pageable pageable);

    List<PolicyEvolutionProposal> findByStatusIn(List<ProposalStatus> statuses);

    @Query("SELECT p FROM PolicyEvolutionProposal p WHERE p.status = 'ACTIVATED'")
    List<PolicyEvolutionProposal> findActiveProposals();

    List<PolicyEvolutionProposal> findByCreatedAtBetween(
        LocalDateTime startDate, 
        LocalDateTime endDate
    );

    @Query("SELECT p FROM PolicyEvolutionProposal p WHERE p.expiresAt < :now AND p.status = 'PENDING'")
    List<PolicyEvolutionProposal> findExpiredProposals(@Param("now") LocalDateTime now);

    @Query("SELECT p FROM PolicyEvolutionProposal p WHERE p.createdAt > :date ORDER BY p.createdAt DESC")
    List<PolicyEvolutionProposal> findRecentProposals(@Param("date") LocalDateTime date);

    List<PolicyEvolutionProposal> findByProposalType(PolicyEvolutionProposal.ProposalType type);

    List<PolicyEvolutionProposal> findByLearningType(LearningMetadata.LearningType learningType);

    List<PolicyEvolutionProposal> findByRiskLevel(PolicyEvolutionProposal.RiskLevel riskLevel);

    @Query("SELECT p FROM PolicyEvolutionProposal p " +
           "WHERE p.status = 'PENDING' " +
           "AND p.riskLevel IN ('HIGH', 'CRITICAL') " +
           "ORDER BY p.riskLevel DESC, p.createdAt ASC")
    List<PolicyEvolutionProposal> findPendingHighRiskProposals();

    @Query("SELECT p FROM PolicyEvolutionProposal p " +
           "WHERE p.status = 'PENDING' " +
           "AND p.riskLevel = 'LOW' " +
           "AND p.confidenceScore >= 0.9")
    List<PolicyEvolutionProposal> findAutoApprovableProposals();

    List<PolicyEvolutionProposal> findByAnalysisLabId(String labId);

    Optional<PolicyEvolutionProposal> findBySourceEventId(String eventId);

    @Query("SELECT p FROM PolicyEvolutionProposal p " +
           "WHERE p.status = 'ACTIVATED' " +
           "AND p.actualImpact >= :threshold " +
           "ORDER BY p.actualImpact DESC")
    List<PolicyEvolutionProposal> findHighImpactProposals(@Param("threshold") Double threshold);

    @Query("SELECT p FROM PolicyEvolutionProposal p " +
           "WHERE p.status = 'ACTIVATED' " +
           "AND ABS(p.expectedImpact - p.actualImpact) > :threshold")
    List<PolicyEvolutionProposal> findProposalsWithImpactDeviation(@Param("threshold") Double threshold);

    @Query("SELECT p.status, COUNT(p) FROM PolicyEvolutionProposal p GROUP BY p.status")
    List<Object[]> countByStatus();

    @Query("SELECT p.proposalType, COUNT(p) FROM PolicyEvolutionProposal p GROUP BY p.proposalType")
    List<Object[]> countByProposalType();

    @Query("SELECT AVG(TIMESTAMPDIFF(HOUR, p.createdAt, p.reviewedAt)) " +
           "FROM PolicyEvolutionProposal p " +
           "WHERE p.reviewedAt IS NOT NULL")
    Double calculateAverageProcessingTime();

    @Query("SELECT " +
           "CAST(COUNT(CASE WHEN p.status IN ('APPROVED', 'ACTIVATED') THEN 1 END) AS DOUBLE) / " +
           "CAST(COUNT(CASE WHEN p.status IN ('APPROVED', 'ACTIVATED', 'REJECTED') THEN 1 END) AS DOUBLE) " +
           "FROM PolicyEvolutionProposal p")
    Double calculateApprovalRate();

    @Modifying
    @Query("UPDATE PolicyEvolutionProposal p SET p.status = :status WHERE p.id = :id")
    void updateStatus(@Param("id") Long id, @Param("status") ProposalStatus status);

    @Modifying
    @Query("UPDATE PolicyEvolutionProposal p SET p.actualImpact = :impact WHERE p.id = :id")
    void updateActualImpact(@Param("id") Long id, @Param("impact") Double impact);

    @Modifying
    @Query("UPDATE PolicyEvolutionProposal p " +
           "SET p.status = 'EXPIRED' " +
           "WHERE p.expiresAt < :now " +
           "AND p.status = 'PENDING'")
    int expireOldProposals(@Param("now") LocalDateTime now);

    Optional<PolicyEvolutionProposal> findByVersionId(Long versionId);

    List<PolicyEvolutionProposal> findByParentProposalId(Long parentId);

    @Query("SELECT p FROM PolicyEvolutionProposal p " +
           "WHERE LOWER(p.title) LIKE LOWER(CONCAT('%', :keyword, '%')) " +
           "OR LOWER(p.description) LIKE LOWER(CONCAT('%', :keyword, '%'))")
    Page<PolicyEvolutionProposal> searchByKeyword(@Param("keyword") String keyword, Pageable pageable);

    List<PolicyEvolutionProposal> findByReviewedBy(String reviewer);

    List<PolicyEvolutionProposal> findByApprovedBy(String approver);

    @Modifying
    @Query("DELETE FROM PolicyEvolutionProposal p " +
           "WHERE p.status = 'REJECTED' " +
           "AND p.reviewedAt < :date")
    int deleteOldRejectedProposals(@Param("date") LocalDateTime date);

    @Modifying
    @Query("DELETE FROM PolicyEvolutionProposal p " +
           "WHERE p.status IN ('DEACTIVATED', 'ROLLED_BACK', 'EXPIRED') " +
           "AND p.createdAt < :date")
    int deleteInactiveProposals(@Param("date") LocalDateTime date);

    @Query("SELECT p FROM PolicyEvolutionProposal p " +
           "WHERE p.status = :status " +
           "AND p.activatedAt < :date")
    List<PolicyEvolutionProposal> findByStatusAndActivatedAtBefore(
        @Param("status") ProposalStatus status, 
        @Param("date") LocalDateTime date
    );
}