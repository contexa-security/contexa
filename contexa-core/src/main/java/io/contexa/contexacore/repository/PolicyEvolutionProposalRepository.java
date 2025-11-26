package io.contexa.contexacore.repository;

import io.contexa.contexacore.domain.entity.PolicyEvolutionProposal;
import io.contexa.contexacore.domain.entity.PolicyEvolutionProposal.ProposalStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

/**
 * 정책 진화 제안 Repository
 *
 * AI가 생성한 정책 제안을 DB에 영구 저장합니다.
 *
 * @author contexa
 * @since 1.0.0
 */
@Repository
public interface PolicyEvolutionProposalRepository extends JpaRepository<PolicyEvolutionProposal, Long> {

    /**
     * 상태별 조회
     */
    List<PolicyEvolutionProposal> findByStatus(ProposalStatus status);

    /**
     * 대기 중인 제안 조회
     */
    @Query("SELECT p FROM PolicyEvolutionProposal p WHERE p.status = 'PENDING_APPROVAL'")
    List<PolicyEvolutionProposal> findPendingProposals();

    /**
     * 날짜 범위로 조회
     */
    List<PolicyEvolutionProposal> findByCreatedAtBetween(LocalDateTime startDate, LocalDateTime endDate);

    /**
     * 생성자별 조회
     */
    List<PolicyEvolutionProposal> findByCreatedBy(String createdBy);

    /**
     * 상태별 카운트
     */
    long countByStatus(ProposalStatus status);
}
