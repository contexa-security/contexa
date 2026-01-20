package io.contexa.contexacore.repository;

import io.contexa.contexacore.domain.entity.SoarApprovalRequest;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;


@Repository
public interface SoarApprovalRequestRepository extends JpaRepository<SoarApprovalRequest, Long> {

    
    List<SoarApprovalRequest> findByStatusOrderByCreatedAtDesc(String status);

    
    @Deprecated
    List<SoarApprovalRequest> findByReviewerIdAndStatus(String reviewerId, String status);
    
    
    List<SoarApprovalRequest> findByApprovedByAndStatus(String approvedBy, String status);

    
    @Deprecated
    List<SoarApprovalRequest> findByPlaybookInstanceId(String playbookInstanceId);
    
    
    List<SoarApprovalRequest> findByIncidentId(String incidentId);
    
    
    SoarApprovalRequest findByRequestId(String requestId);
    
    
    List<SoarApprovalRequest> findBySessionId(String sessionId);
    
    
    List<SoarApprovalRequest> findByRiskLevelOrderByCreatedAtDesc(String riskLevel);
}
