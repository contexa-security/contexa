package io.contexa.contexacore.autonomous;

import io.contexa.contexacore.domain.entity.PolicyEvolutionProposal;
import io.contexa.contexacore.domain.entity.PolicyEvolutionProposal.ProposalStatus;

import java.util.List;
import java.util.Optional;

/**
 * 정책 제안 관리 서비스 인터페이스
 * Community 모듈에서 인터페이스 정의, Enterprise 모듈에서 구현체 제공
 *
 * NotificationService 패턴 적용:
 * - contexa-core: 인터페이스 정의
 * - contexa-core-enterprise: 구현체 제공
 * - 사용처: @Autowired(required = false) + @ConditionalOnBean으로 Optional 주입
 *
 * @author contexa
 * @since 1.0.0
 */
public interface IPolicyProposalManagementService {

    /**
     * 정책 제안 제출
     *
     * @param proposal 제출할 정책 제안
     * @return 저장된 제안의 ID
     */
    Long submitProposal(PolicyEvolutionProposal proposal);

    /**
     * 제안 평가
     *
     * @param proposalId 평가할 제안 ID
     */
    void evaluateProposal(Long proposalId);

    /**
     * 수동 승인
     *
     * @param proposalId 승인할 제안 ID
     * @param approvedBy 승인자
     */
    void approveProposal(Long proposalId, String approvedBy);

    /**
     * 제안 거부
     *
     * @param proposalId 거부할 제안 ID
     * @param rejectedBy 거부자
     * @param reason 거부 사유
     */
    void rejectProposal(Long proposalId, String rejectedBy, String reason);

    /**
     * 제안 조회
     *
     * @param proposalId 조회할 제안 ID
     * @return 제안 Optional
     */
    Optional<PolicyEvolutionProposal> getProposal(Long proposalId);

    /**
     * 모든 제안 조회
     *
     * @return 모든 제안 목록
     */
    List<PolicyEvolutionProposal> getAllProposals();

    /**
     * 대기 중인 제안 조회
     *
     * @return 대기 중인 제안 목록
     */
    List<PolicyEvolutionProposal> getPendingProposals();

    /**
     * 상태별 제안 조회
     *
     * @param status 조회할 상태
     * @return 해당 상태의 제안 목록
     */
    List<PolicyEvolutionProposal> getProposalsByStatus(ProposalStatus status);

    /**
     * 제안 업데이트
     *
     * @param proposalId 업데이트할 제안 ID
     * @param updates 업데이트 내용
     * @return 업데이트된 제안
     */
    PolicyEvolutionProposal updateProposal(Long proposalId, PolicyEvolutionProposal updates);

    /**
     * 제안 삭제
     *
     * @param proposalId 삭제할 제안 ID
     */
    void deleteProposal(Long proposalId);
}
