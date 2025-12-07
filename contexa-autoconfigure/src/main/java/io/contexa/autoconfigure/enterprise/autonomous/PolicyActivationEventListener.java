package io.contexa.autoconfigure.enterprise.autonomous;

import io.contexa.contexacore.domain.entity.PolicyEvolutionProposal;
import io.contexa.contexacore.repository.PolicyProposalRepository;
import io.contexa.contexacoreenterprise.autonomous.evolution.PolicyActivationServiceImpl;
import io.contexa.contexaiam.domain.dto.PolicyDto;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.security.xacml.pap.service.PolicyService;
import io.contexa.contexaiam.security.xacml.pep.CustomDynamicAuthorizationManager;
import io.contexa.contexaiam.security.xacml.prp.PolicyRetrievalPoint;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Map;

/**
 * AI 정책 활성화 이벤트 리스너
 *
 * PolicyActivationServiceImpl에서 발행한 PolicyChangeEvent를 수신하여
 * PolicyEvolutionProposal을 실제 XACML Policy로 변환하고
 * Spring Security에 적용합니다.
 *
 * 정책 흐름:
 * 1. PolicyEvolutionEngine이 PolicyEvolutionProposal 생성
 * 2. 거버넌스 승인 프로세스 (PolicyApprovalService)
 * 3. PolicyActivationServiceImpl이 ACTIVATED 이벤트 발행
 * 4. 이 리스너가 이벤트 수신
 * 5. ProposalToPolicyConverter로 PolicyDto 변환
 * 6. DefaultPolicyService.createPolicy()로 Policy 저장
 * 7. Spring Security 재로드 (CustomDynamicAuthorizationManager)
 *
 * @author contexa
 * @since 1.0.0
 */
@Slf4j
@RequiredArgsConstructor
public class PolicyActivationEventListener {

    private final PolicyProposalRepository proposalRepository;
    private final ProposalToPolicyConverter proposalToPolicyConverter;
    private final PolicyService policyService;
    private final PolicyRetrievalPoint policyRetrievalPoint;
    private final CustomDynamicAuthorizationManager authorizationManager;

    /**
     * AI 정책 활성화 이벤트 처리
     *
     * PolicyActivationServiceImpl.PolicyChangeEvent (ACTIVATED 타입)를 수신하여
     * 실제 Spring Security 정책으로 변환하고 적용합니다.
     *
     * @param event 정책 변경 이벤트
     */
    @EventListener
    @Async
    @Transactional
    public void handlePolicyActivatedEvent(PolicyActivationServiceImpl.PolicyChangeEvent event) {
        if (event.getChangeType() != PolicyActivationServiceImpl.PolicyChangeType.ACTIVATED) {
            log.debug("ACTIVATED가 아닌 이벤트 무시: type={}", event.getChangeType());
            return;
        }

        Long proposalId = event.getProposalId();
        log.info("AI 정책 활성화 이벤트 수신: proposalId={}", proposalId);

        try {
            // 1. PolicyEvolutionProposal 조회
            PolicyEvolutionProposal proposal = proposalRepository.findById(proposalId)
                    .orElseThrow(() -> new IllegalArgumentException(
                            "PolicyEvolutionProposal을 찾을 수 없습니다: proposalId=" + proposalId));

            // 2. 이미 Policy가 생성되었는지 확인
            if (proposal.getPolicyId() != null) {
                log.info("이미 Policy가 생성되어 있습니다: proposalId={}, policyId={}",
                        proposalId, proposal.getPolicyId());
                // 기존 정책 재활성화
                reactivateExistingPolicy(proposal);
                return;
            }

            // 3. PolicyEvolutionProposal -> PolicyDto 변환
            PolicyDto policyDto = proposalToPolicyConverter.convert(proposal);
            log.info("PolicyDto 변환 완료: policyName={}", policyDto.getName());

            // 4. XACML PAP에 정책 저장
            Policy savedPolicy = policyService.createPolicy(policyDto);
            log.info("XACML Policy 저장 완료: policyId={}, policyName={}",
                    savedPolicy.getId(), savedPolicy.getName());

            // 5. AI 생성 정책 메타데이터 설정
            updatePolicyForAIGenerated(savedPolicy, proposal);

            // 6. PolicyEvolutionProposal에 생성된 Policy ID 기록
            linkProposalToPolicy(proposal, savedPolicy);

            // 7. Spring Security 재로드 (이미 DefaultPolicyService에서 처리됨)
            log.info("AI 정책이 Spring Security에 적용됨: proposalId={}, policyId={}",
                    proposalId, savedPolicy.getId());

        } catch (Exception e) {
            log.error("AI 정책 활성화 실패: proposalId={}, error={}",
                    proposalId, e.getMessage(), e);
            // 실패 시 제안 상태를 롤백하지 않음 (PolicyActivationServiceImpl에서 별도 처리)
            throw new RuntimeException("AI 정책 활성화 실패: " + e.getMessage(), e);
        }
    }

    /**
     * AI 정책 비활성화 이벤트 처리
     *
     * @param event 정책 변경 이벤트
     */
    @EventListener
    @Async
    @Transactional
    public void handlePolicyDeactivatedEvent(PolicyActivationServiceImpl.PolicyChangeEvent event) {
        if (event.getChangeType() != PolicyActivationServiceImpl.PolicyChangeType.DEACTIVATED) {
            return;
        }

        Long proposalId = event.getProposalId();
        log.info("AI 정책 비활성화 이벤트 수신: proposalId={}", proposalId);

        try {
            PolicyEvolutionProposal proposal = proposalRepository.findById(proposalId)
                    .orElseThrow(() -> new IllegalArgumentException(
                            "PolicyEvolutionProposal을 찾을 수 없습니다: proposalId=" + proposalId));

            if (proposal.getPolicyId() != null) {
                // 정책 비활성화 (삭제하지 않고 비활성화만)
                deactivatePolicy(proposal.getPolicyId());
                log.info("AI 정책 비활성화 완료: proposalId={}, policyId={}",
                        proposalId, proposal.getPolicyId());
            } else {
                log.warn("연결된 Policy가 없습니다: proposalId={}", proposalId);
            }

        } catch (Exception e) {
            log.error("AI 정책 비활성화 실패: proposalId={}, error={}",
                    proposalId, e.getMessage(), e);
        }
    }

    /**
     * AI 정책 롤백 이벤트 처리
     *
     * @param event 정책 변경 이벤트
     */
    @EventListener
    @Async
    @Transactional
    public void handlePolicyRolledBackEvent(PolicyActivationServiceImpl.PolicyChangeEvent event) {
        if (event.getChangeType() != PolicyActivationServiceImpl.PolicyChangeType.ROLLED_BACK) {
            return;
        }

        Long proposalId = event.getProposalId();
        log.info("AI 정책 롤백 이벤트 수신: proposalId={}", proposalId);

        try {
            PolicyEvolutionProposal proposal = proposalRepository.findById(proposalId)
                    .orElseThrow(() -> new IllegalArgumentException(
                            "PolicyEvolutionProposal을 찾을 수 없습니다: proposalId=" + proposalId));

            if (proposal.getPolicyId() != null) {
                // 정책 완전 삭제
                policyService.deletePolicy(proposal.getPolicyId());
                log.info("AI 정책 롤백(삭제) 완료: proposalId={}, policyId={}",
                        proposalId, proposal.getPolicyId());

                // 제안에서 Policy ID 연결 해제
                proposal.setPolicyId(null);
                proposalRepository.save(proposal);
            } else {
                log.warn("롤백할 Policy가 없습니다: proposalId={}", proposalId);
            }

        } catch (Exception e) {
            log.error("AI 정책 롤백 실패: proposalId={}, error={}",
                    proposalId, e.getMessage(), e);
        }
    }

    /**
     * 기존 정책 재활성화
     */
    private void reactivateExistingPolicy(PolicyEvolutionProposal proposal) {
        try {
            Policy existingPolicy = policyService.findById(proposal.getPolicyId());

            // 정책 활성화
            existingPolicy.setIsActive(true);
            existingPolicy.activate();

            // Spring Security 재로드
            reloadAuthorizationSystem();

            log.info("기존 정책 재활성화 완료: policyId={}", proposal.getPolicyId());

        } catch (Exception e) {
            log.error("기존 정책 재활성화 실패: policyId={}, error={}",
                    proposal.getPolicyId(), e.getMessage(), e);
        }
    }

    /**
     * AI 생성 정책 메타데이터 업데이트
     */
    private void updatePolicyForAIGenerated(Policy policy, PolicyEvolutionProposal proposal) {
        // AI 생성 정책 출처 설정
        if (proposal.getParentProposalId() != null) {
            policy.setSource(Policy.PolicySource.AI_EVOLVED);
        } else {
            policy.setSource(Policy.PolicySource.AI_GENERATED);
        }

        // 승인 상태 설정
        policy.setApprovalStatus(Policy.ApprovalStatus.APPROVED);
        policy.setApprovedBy(proposal.getApprovedBy());
        policy.setApprovedAt(LocalDateTime.now());

        // 신뢰도 점수 설정
        policy.setConfidenceScore(proposal.getConfidenceScore());

        // AI 모델 정보 설정 (있는 경우)
        Map<String, Object> metadata = proposal.getMetadata();
        if (metadata != null && metadata.containsKey("aiModel")) {
            policy.setAiModel(String.valueOf(metadata.get("aiModel")));
        }

        policy.setUpdatedAt(LocalDateTime.now());

        log.debug("AI 정책 메타데이터 업데이트: policyId={}, source={}, confidenceScore={}",
                policy.getId(), policy.getSource(), policy.getConfidenceScore());
    }

    /**
     * PolicyEvolutionProposal과 Policy 연결
     */
    private void linkProposalToPolicy(PolicyEvolutionProposal proposal, Policy policy) {
        proposal.setPolicyId(policy.getId());
        proposal.addMetadata("linked_policy_name", policy.getName());
        proposal.addMetadata("linked_at", LocalDateTime.now().toString());
        proposalRepository.save(proposal);

        log.debug("Proposal-Policy 연결 완료: proposalId={}, policyId={}",
                proposal.getId(), policy.getId());
    }

    /**
     * 정책 비활성화
     */
    private void deactivatePolicy(Long policyId) {
        try {
            Policy policy = policyService.findById(policyId);
            policy.setIsActive(false);
            policy.deactivate();

            // Spring Security 재로드
            reloadAuthorizationSystem();

        } catch (Exception e) {
            log.error("정책 비활성화 중 오류: policyId={}", policyId, e);
        }
    }

    /**
     * Spring Security 인가 시스템 재로드
     */
    private void reloadAuthorizationSystem() {
        try {
            policyRetrievalPoint.clearUrlPoliciesCache();
            policyRetrievalPoint.clearMethodPoliciesCache();
            authorizationManager.reload();
            log.debug("인가 시스템 재로드 완료");
        } catch (Exception e) {
            log.error("인가 시스템 재로드 실패", e);
        }
    }
}
