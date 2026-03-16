package io.contexa.contexacore.repository;

import io.contexa.contexacore.domain.entity.SoarApprovalStep;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

@Repository
public interface SoarApprovalStepRepository extends JpaRepository<SoarApprovalStep, Long> {

    List<SoarApprovalStep> findByRequestIdOrderByStepNumberAsc(String requestId);

    List<SoarApprovalStep> findByRequestIdInOrderByStepNumberAsc(Collection<String> requestIds);

    Optional<SoarApprovalStep> findByRequestIdAndStepNumber(String requestId, Integer stepNumber);

    Optional<SoarApprovalStep> findFirstByRequestIdAndStatusOrderByStepNumberAsc(String requestId, String status);

    void deleteByRequestId(String requestId);
}
