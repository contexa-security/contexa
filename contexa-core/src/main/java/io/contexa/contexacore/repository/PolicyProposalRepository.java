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

/**
 * 정책 제안 저장소
 * 
 * PolicyEvolutionProposal 엔티티에 대한 데이터 액세스 계층입니다.
 * 
 * @author AI3Security
 * @since 1.0.0
 */
@Repository
public interface PolicyProposalRepository extends JpaRepository<PolicyEvolutionProposal, Long> {
    
    // ==================== 상태별 조회 ====================
    
    /**
     * 상태별 제안 조회
     */
    List<PolicyEvolutionProposal> findByStatus(ProposalStatus status);
    
    /**
     * 상태별 제안 페이징 조회
     */
    Page<PolicyEvolutionProposal> findByStatus(ProposalStatus status, Pageable pageable);
    
    /**
     * 여러 상태의 제안 조회
     */
    List<PolicyEvolutionProposal> findByStatusIn(List<ProposalStatus> statuses);
    
    /**
     * 활성화된 제안 조회
     */
    @Query("SELECT p FROM PolicyEvolutionProposal p WHERE p.status = 'ACTIVATED'")
    List<PolicyEvolutionProposal> findActiveProposals();
    
    // ==================== 시간 기반 조회 ====================
    
    /**
     * 특정 기간 내 생성된 제안 조회
     */
    List<PolicyEvolutionProposal> findByCreatedAtBetween(
        LocalDateTime startDate, 
        LocalDateTime endDate
    );
    
    /**
     * 만료된 제안 조회
     */
    @Query("SELECT p FROM PolicyEvolutionProposal p WHERE p.expiresAt < :now AND p.status = 'PENDING'")
    List<PolicyEvolutionProposal> findExpiredProposals(@Param("now") LocalDateTime now);
    
    /**
     * 최근 N일 내 생성된 제안 조회
     */
    @Query("SELECT p FROM PolicyEvolutionProposal p WHERE p.createdAt > :date ORDER BY p.createdAt DESC")
    List<PolicyEvolutionProposal> findRecentProposals(@Param("date") LocalDateTime date);
    
    // ==================== 유형별 조회 ====================
    
    /**
     * 제안 유형별 조회
     */
    List<PolicyEvolutionProposal> findByProposalType(PolicyEvolutionProposal.ProposalType type);
    
    /**
     * 학습 유형별 조회
     */
    List<PolicyEvolutionProposal> findByLearningType(LearningMetadata.LearningType learningType);
    
    /**
     * 위험 수준별 조회
     */
    List<PolicyEvolutionProposal> findByRiskLevel(PolicyEvolutionProposal.RiskLevel riskLevel);
    
    // ==================== 복합 조건 조회 ====================
    
    /**
     * 대기 중인 고위험 제안 조회
     */
    @Query("SELECT p FROM PolicyEvolutionProposal p " +
           "WHERE p.status = 'PENDING' " +
           "AND p.riskLevel IN ('HIGH', 'CRITICAL') " +
           "ORDER BY p.riskLevel DESC, p.createdAt ASC")
    List<PolicyEvolutionProposal> findPendingHighRiskProposals();
    
    /**
     * 자동 승인 가능한 제안 조회
     */
    @Query("SELECT p FROM PolicyEvolutionProposal p " +
           "WHERE p.status = 'PENDING' " +
           "AND p.riskLevel = 'LOW' " +
           "AND p.confidenceScore >= 0.9")
    List<PolicyEvolutionProposal> findAutoApprovableProposals();
    
    /**
     * 특정 Lab이 생성한 제안 조회
     */
    List<PolicyEvolutionProposal> findByAnalysisLabId(String labId);
    
    /**
     * 특정 이벤트로부터 생성된 제안 조회
     */
    Optional<PolicyEvolutionProposal> findBySourceEventId(String eventId);
    
    // ==================== 효과성 관련 조회 ====================
    
    /**
     * 높은 효과를 보인 제안 조회
     */
    @Query("SELECT p FROM PolicyEvolutionProposal p " +
           "WHERE p.status = 'ACTIVATED' " +
           "AND p.actualImpact >= :threshold " +
           "ORDER BY p.actualImpact DESC")
    List<PolicyEvolutionProposal> findHighImpactProposals(@Param("threshold") Double threshold);
    
    /**
     * 예상과 실제 영향도 차이가 큰 제안 조회
     */
    @Query("SELECT p FROM PolicyEvolutionProposal p " +
           "WHERE p.status = 'ACTIVATED' " +
           "AND ABS(p.expectedImpact - p.actualImpact) > :threshold")
    List<PolicyEvolutionProposal> findProposalsWithImpactDeviation(@Param("threshold") Double threshold);
    
    // ==================== 통계 조회 ====================
    
    /**
     * 상태별 제안 수 집계
     */
    @Query("SELECT p.status, COUNT(p) FROM PolicyEvolutionProposal p GROUP BY p.status")
    List<Object[]> countByStatus();
    
    /**
     * 유형별 제안 수 집계
     */
    @Query("SELECT p.proposalType, COUNT(p) FROM PolicyEvolutionProposal p GROUP BY p.proposalType")
    List<Object[]> countByProposalType();
    
    /**
     * 평균 처리 시간 계산
     */
    @Query("SELECT AVG(TIMESTAMPDIFF(HOUR, p.createdAt, p.reviewedAt)) " +
           "FROM PolicyEvolutionProposal p " +
           "WHERE p.reviewedAt IS NOT NULL")
    Double calculateAverageProcessingTime();
    
    /**
     * 승인율 계산
     */
    @Query("SELECT " +
           "CAST(COUNT(CASE WHEN p.status IN ('APPROVED', 'ACTIVATED') THEN 1 END) AS DOUBLE) / " +
           "CAST(COUNT(CASE WHEN p.status IN ('APPROVED', 'ACTIVATED', 'REJECTED') THEN 1 END) AS DOUBLE) " +
           "FROM PolicyEvolutionProposal p")
    Double calculateApprovalRate();
    
    // ==================== 업데이트 작업 ====================
    
    /**
     * 상태 업데이트
     */
    @Modifying
    @Query("UPDATE PolicyEvolutionProposal p SET p.status = :status WHERE p.id = :id")
    void updateStatus(@Param("id") Long id, @Param("status") ProposalStatus status);
    
    /**
     * 실제 영향도 업데이트
     */
    @Modifying
    @Query("UPDATE PolicyEvolutionProposal p SET p.actualImpact = :impact WHERE p.id = :id")
    void updateActualImpact(@Param("id") Long id, @Param("impact") Double impact);
    
    /**
     * 만료된 제안 상태 업데이트
     */
    @Modifying
    @Query("UPDATE PolicyEvolutionProposal p " +
           "SET p.status = 'EXPIRED' " +
           "WHERE p.expiresAt < :now " +
           "AND p.status = 'PENDING'")
    int expireOldProposals(@Param("now") LocalDateTime now);
    
    // ==================== 버전 관련 조회 ====================
    
    /**
     * 특정 버전의 제안 조회
     */
    Optional<PolicyEvolutionProposal> findByVersionId(Long versionId);
    
    /**
     * 부모 제안으로부터 파생된 제안들 조회
     */
    List<PolicyEvolutionProposal> findByParentProposalId(Long parentId);
    
    // ==================== 검색 ====================
    
    /**
     * 제목 또는 설명으로 검색
     */
    @Query("SELECT p FROM PolicyEvolutionProposal p " +
           "WHERE LOWER(p.title) LIKE LOWER(CONCAT('%', :keyword, '%')) " +
           "OR LOWER(p.description) LIKE LOWER(CONCAT('%', :keyword, '%'))")
    Page<PolicyEvolutionProposal> searchByKeyword(@Param("keyword") String keyword, Pageable pageable);
    
    /**
     * 관리자별 검토한 제안 조회
     */
    List<PolicyEvolutionProposal> findByReviewedBy(String reviewer);
    
    /**
     * 승인자별 승인한 제안 조회
     */
    List<PolicyEvolutionProposal> findByApprovedBy(String approver);
    
    // ==================== 정리 작업 ====================
    
    /**
     * 오래된 거부된 제안 삭제
     */
    @Modifying
    @Query("DELETE FROM PolicyEvolutionProposal p " +
           "WHERE p.status = 'REJECTED' " +
           "AND p.reviewedAt < :date")
    int deleteOldRejectedProposals(@Param("date") LocalDateTime date);
    
    /**
     * 특정 기간 이전의 비활성 제안 삭제
     */
    @Modifying
    @Query("DELETE FROM PolicyEvolutionProposal p " +
           "WHERE p.status IN ('DEACTIVATED', 'ROLLED_BACK', 'EXPIRED') " +
           "AND p.createdAt < :date")
    int deleteInactiveProposals(@Param("date") LocalDateTime date);
    
    /**
     * 특정 상태와 활성화 시간 이전 제안 조회
     */
    @Query("SELECT p FROM PolicyEvolutionProposal p " +
           "WHERE p.status = :status " +
           "AND p.activatedAt < :date")
    List<PolicyEvolutionProposal> findByStatusAndActivatedAtBefore(
        @Param("status") ProposalStatus status, 
        @Param("date") LocalDateTime date
    );
}