package io.contexa.contexacore.repository;

import io.contexa.contexacore.domain.entity.SoarApprovalAssignment;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

@Repository
public interface SoarApprovalAssignmentRepository extends JpaRepository<SoarApprovalAssignment, Long> {

    List<SoarApprovalAssignment> findByRequestIdOrderByStepNumberAscCreatedAtAsc(String requestId);

    List<SoarApprovalAssignment> findByRequestIdInOrderByStepNumberAscCreatedAtAsc(Collection<String> requestIds);

    List<SoarApprovalAssignment> findByRequestIdAndStepNumberOrderByCreatedAtAsc(String requestId, Integer stepNumber);

    List<SoarApprovalAssignment> findByRequestIdAndStepNumberAndStatusOrderByCreatedAtAsc(String requestId, Integer stepNumber, String status);

    Optional<SoarApprovalAssignment> findByRequestIdAndStepNumberAndAssigneeId(String requestId, Integer stepNumber, String assigneeId);

    void deleteByRequestId(String requestId);
}
