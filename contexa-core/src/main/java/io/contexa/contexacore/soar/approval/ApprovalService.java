package io.contexa.contexacore.soar.approval;

import io.contexa.contexacore.domain.SoarContext;
import io.contexa.contexacore.domain.ApprovalRequest;

import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

import reactor.core.publisher.Mono;

/**
 * SOAR Approval Service Interface
 *
 * <p>
 * SOAR 워크플로우 중 관리자의 승인이 필요한 단계를 처리하는 서비스 인터페이스.
 * Enterprise 모듈에서 구현체를 제공합니다.
 * </p>
 *
 * @since 0.1.1
 */
public interface ApprovalService {

    /**
     * 새로운 승인 요청을 생성하고 관리자에게 알린다.
     *
     * @param soarContext 현재 SOAR 컨텍스트
     * @param requestDetails 승인 요청에 대한 상세 내용
     * @return 생성된 승인 요청의 고유 ID
     */
    String requestApproval(SoarContext soarContext, ApprovalRequestDetails requestDetails);

    /**
     * 승인 요청의 현재 상태를 조회한다.
     *
     * @param approvalId 조회할 승인 요청 ID
     * @return 승인 상태
     */
    ApprovalRequest.ApprovalStatus getApprovalStatus(String approvalId);

    /**
     * 관리자가 승인/거부 의사를 표시했을 때 호출되는 콜백 메소드.
     *
     * @param approvalId 처리된 승인 요청 ID
     * @param isApproved 승인 여부
     * @param comment 관리자 코멘트
     * @param reviewer 검토자
     */
    void handleApprovalResponse(String approvalId, boolean isApproved, String comment, String reviewer);

    /**
     * 대기 중인 승인 요청 ID 목록을 조회한다.
     *
     * @return 대기 중인 승인 요청 ID 목록
     */
    Set<String> getPendingApprovalIds();

    /**
     * 대기 중인 승인 요청 개수를 조회한다.
     *
     * @return 대기 중인 승인 요청 개수
     */
    int getPendingCount();

    /**
     * 통합 승인 요청 (CompletableFuture 기반)
     *
     * @param request 승인 요청
     * @return 승인 결과를 담은 CompletableFuture (true: 승인, false: 거부)
     */
    default CompletableFuture<Boolean> requestApproval(ApprovalRequest request) {
        throw new UnsupportedOperationException("requestApproval(ApprovalRequest) not implemented");
    }

    /**
     * 승인 응답 처리 (통합 메서드)
     *
     * @param requestId 승인 요청 ID
     * @param approved 승인 여부
     * @param reviewer 검토자
     * @param comment 코멘트
     */
    default void processApprovalResponse(String requestId, boolean approved, String reviewer, String comment) {
        handleApprovalResponse(requestId, approved, comment, reviewer);
    }

    /**
     * 동기식 승인 대기
     *
     * @param request 승인 요청
     * @return 승인 여부 (true: 승인, false: 거부 또는 타임아웃)
     */
    default boolean waitForApprovalSync(ApprovalRequest request) {
        throw new UnsupportedOperationException("waitForApprovalSync not implemented");
    }

    /**
     * 승인 요청 저장 (새로운 ApprovalRequest 도메인 모델 사용)
     * ApprovalCheckStep에서 사용
     */
    default ApprovalRequest saveApprovalRequest(ApprovalRequest request) {
        throw new UnsupportedOperationException("saveApprovalRequest not implemented");
    }

    /**
     * 승인 알림 발송
     * ApprovalCheckStep에서 사용
     */
    default void sendApprovalNotification(ApprovalRequest request) {
        throw new UnsupportedOperationException("sendApprovalNotification not implemented");
    }

    /**
     * 승인 대기 (비동기)
     * ApprovalCheckStep에서 사용
     *
     * @param requestId 승인 요청 ID
     * @return 승인 여부 (true: 승인, false: 거부)
     */
    default Mono<Boolean> waitForApproval(String requestId) {
        return Mono.defer(() -> {
            ApprovalRequest.ApprovalStatus status = getApprovalStatus(requestId);
            return Mono.just(status == ApprovalRequest.ApprovalStatus.APPROVED);
        });
    }

    /**
     * 승인 처리 (컨트롤러에서 사용)
     *
     * @param approvalId 승인 요청 ID
     * @param approved 승인 여부
     * @param reason 승인/거부 사유
     */
    default void processApproval(String approvalId, boolean approved, String reason) {
        handleApprovalResponse(approvalId, approved, reason, "system");
    }

    /**
     * 대기 중인 승인 목록 조회
     *
     * @return 대기 중인 승인 요청 목록
     */
    default List<ApprovalRequest> getPendingApprovals() {
        return List.of();
    }

    /**
     * 승인 요청 제출
     */
    default void submitApprovalRequest(ApprovalRequest request) {
        saveApprovalRequest(request);
        sendApprovalNotification(request);
    }

    /**
     * 승인 처리 (ID만으로)
     */
    default void approve(String approvalId) {
        handleApprovalResponse(approvalId, true, "Approved", "system");
    }

    /**
     * 거부 처리 (ID만으로)
     */
    default void reject(String approvalId) {
        handleApprovalResponse(approvalId, false, "Rejected", "system");
    }

    /**
     * 승인 요청 조회
     * AsyncApprovalBridge에서 사용
     */
    default ApprovalRequest getApprovalRequest(String approvalId) {
        return null;
    }
}
