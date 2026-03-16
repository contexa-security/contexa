package io.contexa.contexacore.repository;

import io.contexa.contexacore.domain.entity.SoarApprovalVote;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

@Repository
public interface SoarApprovalVoteRepository extends JpaRepository<SoarApprovalVote, Long> {

    List<SoarApprovalVote> findByRequestIdOrderByCreatedAtAsc(String requestId);

    List<SoarApprovalVote> findByRequestIdInOrderByCreatedAtAsc(Collection<String> requestIds);

    List<SoarApprovalVote> findByRequestIdAndStepNumberOrderByCreatedAtAsc(String requestId, Integer stepNumber);

    Optional<SoarApprovalVote> findByRequestIdAndApproverIdAndStepNumber(String requestId, String approverId, Integer stepNumber);

    boolean existsByRequestIdAndApproverIdAndStepNumber(String requestId, String approverId, Integer stepNumber);

    void deleteByRequestId(String requestId);
}
