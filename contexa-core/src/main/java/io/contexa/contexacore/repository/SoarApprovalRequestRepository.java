package io.contexa.contexacore.repository;

import io.contexa.contexacore.domain.entity.SoarApprovalRequest;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * SOAR 승인 요청에 대한 데이터 접근을 처리하는 리포지토리.
 */
@Repository
public interface SoarApprovalRequestRepository extends JpaRepository<SoarApprovalRequest, Long> {

    /**
     * 특정 상태의 모든 승인 요청을 최신순으로 조회합니다.
     * 관리자 대시보드에서 PENDING 상태의 요청 목록을 보여주는 데 사용됩니다.
     * @param status 조회할 상태 (e.g., "PENDING")
     * @return 해당 상태의 승인 요청 목록
     */
    List<SoarApprovalRequest> findByStatusOrderByCreatedAtDesc(String status);

    /**
     * 특정 검토자가 처리한 특정 상태의 모든 승인 요청을 조회합니다.
     * 관리자가 자신이 처리한 내역을 추적하는 데 사용됩니다.
     * @deprecated Use {@link #findByApprovedByAndStatus(String, String)} instead
     * @param reviewerId 검토자의 ID
     * @param status 조회할 상태 (e.g., "APPROVED", "REJECTED")
     * @return 해당 조건의 승인 요청 목록
     */
    @Deprecated
    List<SoarApprovalRequest> findByReviewerIdAndStatus(String reviewerId, String status);
    
    /**
     * 특정 승인자가 처리한 특정 상태의 모든 승인 요청을 조회합니다.
     * 관리자가 자신이 처리한 내역을 추적하는 데 사용됩니다.
     * @param approvedBy 승인자 ID
     * @param status 조회할 상태 (e.g., "APPROVED", "REJECTED")
     * @return 해당 조건의 승인 요청 목록
     */
    List<SoarApprovalRequest> findByApprovedByAndStatus(String approvedBy, String status);

    /**
     * 특정 플레이북 인스턴스와 관련된 모든 승인 요청을 조회합니다.
     * SOAR 케이스의 전체 히스토리를 감사하는 데 사용됩니다.
     * @deprecated Use {@link #findByIncidentId(String)} instead
     * @param playbookInstanceId 플레이북 인스턴스의 UUID 문자열
     * @return 해당 인스턴스와 관련된 승인 요청 목록
     */
    @Deprecated
    List<SoarApprovalRequest> findByPlaybookInstanceId(String playbookInstanceId);
    
    /**
     * 특정 인시던트와 관련된 모든 승인 요청을 조회합니다.
     * SOAR 케이스의 전체 히스토리를 감사하는 데 사용됩니다.
     * @param incidentId 인시던트 ID
     * @return 해당 인시던트와 관련된 승인 요청 목록
     */
    List<SoarApprovalRequest> findByIncidentId(String incidentId);
    
    /**
     * 특정 요청 ID로 승인 요청을 조회합니다.
     * @param requestId 요청 ID
     * @return 승인 요청 (Optional)
     */
    SoarApprovalRequest findByRequestId(String requestId);
    
    /**
     * 특정 세션 ID로 승인 요청을 조회합니다.
     * @param sessionId 세션 ID
     * @return 해당 세션의 승인 요청 목록
     */
    List<SoarApprovalRequest> findBySessionId(String sessionId);
    
    /**
     * 특정 위험 수준의 승인 요청을 조회합니다.
     * @param riskLevel 위험 수준 (CRITICAL/HIGH/MEDIUM/LOW/INFO)
     * @return 해당 위험 수준의 승인 요청 목록
     */
    List<SoarApprovalRequest> findByRiskLevelOrderByCreatedAtDesc(String riskLevel);
}
