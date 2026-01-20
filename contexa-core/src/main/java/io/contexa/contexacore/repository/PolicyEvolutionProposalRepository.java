package io.contexa.contexacore.repository;

import io.contexa.contexacore.domain.entity.PolicyEvolutionProposal;
import io.contexa.contexacore.domain.entity.PolicyEvolutionProposal.ProposalStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;


@Repository
public interface PolicyEvolutionProposalRepository extends JpaRepository<PolicyEvolutionProposal, Long> {

    
    List<PolicyEvolutionProposal> findByStatus(ProposalStatus status);

    
    @Query("SELECT p FROM PolicyEvolutionProposal p WHERE p.status = 'PENDING_APPROVAL'")
    List<PolicyEvolutionProposal> findPendingProposals();

    
    List<PolicyEvolutionProposal> findByCreatedAtBetween(LocalDateTime startDate, LocalDateTime endDate);

    
    List<PolicyEvolutionProposal> findByCreatedBy(String createdBy);

    
    long countByStatus(ProposalStatus status);
}
