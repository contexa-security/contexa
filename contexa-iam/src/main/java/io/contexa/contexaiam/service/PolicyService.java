package io.contexa.contexaiam.service;

import io.contexa.contexacore.autonomous.event.PolicyApprovedEvent;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.domain.entity.policy.PolicyRule;
import io.contexa.contexaiam.domain.entity.policy.PolicyTarget;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.security.xacml.prp.DatabasePolicyRetrievalPoint;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.event.EventListener;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.scheduling.annotation.Async;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.core.type.TypeReference;

/**
 * Policy Service
 *
 * 정책 관리 서비스입니다. AI 생성 정책의 승인/거부 처리를 포함합니다.
 *
 * @author contexa
 * @since 3.1.0
 */
@Slf4j
@RequiredArgsConstructor
public class PolicyService {

    private final PolicyRepository policyRepository;
    private final ApplicationEventPublisher eventPublisher;

    @Autowired(required = false)
    private DatabasePolicyRetrievalPoint policyRetrievalPoint;

    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * ID로 정책 조회
     */
    @Transactional(readOnly = true)
    public Policy findById(Long id) {
        return policyRepository.findById(id).orElse(null);
    }

    /**
     * 정책 저장
     */
    @Transactional
    public Policy save(Policy policy) {
        Policy savedPolicy = policyRepository.save(policy);
        log.info("정책 저장: {}", savedPolicy.getName());

        // PolicyChangeEvent 발행 (실제 구현에서)
        // eventPublisher.publishEvent(new PolicyChangeEvent(...));

        return savedPolicy;
    }

    /**
     * 승인 대기 중인 AI 정책 조회
     */
    @Transactional(readOnly = true)
    public Page<Policy> findPendingAIPolicies(Pageable pageable) {
        return policyRepository.findBySourceInAndApprovalStatus(
            java.util.Arrays.asList(
                Policy.PolicySource.AI_GENERATED,
                Policy.PolicySource.AI_EVOLVED
            ),
            Policy.ApprovalStatus.PENDING,
            pageable
        );
    }

    /**
     * AI 정책 조회 (조건별)
     */
    @Transactional(readOnly = true)
    public Page<Policy> findAIPolicies(Policy.PolicySource source,
                                       Policy.ApprovalStatus status,
                                       Pageable pageable) {
        if (source != null && status != null) {
            return policyRepository.findBySourceAndApprovalStatus(source, status, pageable);
        } else if (source != null) {
            return policyRepository.findBySource(source, pageable);
        } else if (status != null) {
            return policyRepository.findBySourceInAndApprovalStatus(
                java.util.Arrays.asList(
                    Policy.PolicySource.AI_GENERATED,
                    Policy.PolicySource.AI_EVOLVED
                ),
                status,
                pageable
            );
        } else {
            return policyRepository.findBySourceIn(
                java.util.Arrays.asList(
                    Policy.PolicySource.AI_GENERATED,
                    Policy.PolicySource.AI_EVOLVED
                ),
                pageable
            );
        }
    }

    /**
     * AI 정책 수 계산
     */
    @Transactional(readOnly = true)
    public long countAIPolicies() {
        return policyRepository.countBySourceIn(
            java.util.Arrays.asList(
                Policy.PolicySource.AI_GENERATED,
                Policy.PolicySource.AI_EVOLVED
            )
        );
    }

    /**
     * 상태별 AI 정책 수 계산
     */
    @Transactional(readOnly = true)
    public Map<String, Long> countAIPoliciesByStatus() {
        Map<String, Long> counts = new HashMap<>();

        for (Policy.ApprovalStatus status : Policy.ApprovalStatus.values()) {
            long count = policyRepository.countBySourceInAndApprovalStatus(
                java.util.Arrays.asList(
                    Policy.PolicySource.AI_GENERATED,
                    Policy.PolicySource.AI_EVOLVED
                ),
                status
            );
            counts.put(status.name(), count);
        }

        return counts;
    }

    /**
     * 출처별 AI 정책 수 계산
     */
    @Transactional(readOnly = true)
    public Map<String, Long> countAIPoliciesBySource() {
        Map<String, Long> counts = new HashMap<>();

        counts.put(Policy.PolicySource.AI_GENERATED.name(),
            policyRepository.countBySource(Policy.PolicySource.AI_GENERATED));
        counts.put(Policy.PolicySource.AI_EVOLVED.name(),
            policyRepository.countBySource(Policy.PolicySource.AI_EVOLVED));

        return counts;
    }

    /**
     * 승인율 계산
     */
    @Transactional(readOnly = true)
    public double calculateApprovalRate(int days) {
        LocalDateTime since = LocalDateTime.now().minusDays(days);

        long totalProcessed = policyRepository.countBySourceInAndApprovalStatusInAndUpdatedAtAfter(
            java.util.Arrays.asList(
                Policy.PolicySource.AI_GENERATED,
                Policy.PolicySource.AI_EVOLVED
            ),
            java.util.Arrays.asList(
                Policy.ApprovalStatus.APPROVED,
                Policy.ApprovalStatus.REJECTED
            ),
            since
        );

        if (totalProcessed == 0) {
            return 0.0;
        }

        long approved = policyRepository.countBySourceInAndApprovalStatusAndUpdatedAtAfter(
            java.util.Arrays.asList(
                Policy.PolicySource.AI_GENERATED,
                Policy.PolicySource.AI_EVOLVED
            ),
            Policy.ApprovalStatus.APPROVED,
            since
        );

        return (double) approved / totalProcessed * 100;
    }

    /**
     * 평균 신뢰도 점수 계산
     */
    @Transactional(readOnly = true)
    public double calculateAverageConfidenceScore() {
        Double avg = policyRepository.calculateAverageConfidenceScoreForAIPolicies();
        return avg != null ? avg : 0.0;
    }

    /**
     * 거부 사유 기록
     */
    @Transactional
    public void recordRejectionReason(Long policyId, String reason) {
        log.info("정책 거부 사유 기록 - policyId: {}, reason: {}", policyId, reason);

        // 실제 구현에서는 별도 테이블에 저장하거나
        // PolicyChangeEvent를 발행하여 학습 시스템에 전달
    }

    /**
     * PolicyApprovedEvent 리스너 - Evolution → AIAM 피드백 완료
     */
    @EventListener
    @Async
    @Transactional
    public void onPolicyApproved(PolicyApprovedEvent event) {
        try {
            log.info("Received PolicyApprovedEvent: {} approved by {} for target {}",
                event.getPolicyId(), event.getApprovedBy(), event.getTargetSystem());

            // 1. 정책 규칙 파싱 및 검증
            Map<String, Object> policyRules = parsePolicyRules(event.getPolicyRules());
            if (!validatePolicyRules(policyRules)) {
                log.error("Invalid policy rules in PolicyApprovedEvent: {}", event.getPolicyId());
                return;
            }

            // 2. AIAM에 정책 적용 - 새로운 정책 생성
            Policy policy = Policy.builder()
                .name(event.getPolicyName())
                .description(event.getPolicyDescription())
                .effect(determineEffectFromRules(policyRules)) // 규칙에서 결정
                .priority(determinePriorityFromRules(policyRules)) // 규칙에서 결정
                .source(Policy.PolicySource.AI_EVOLVED)
                .approvalStatus(Policy.ApprovalStatus.APPROVED)
                .confidenceScore(event.getConfidenceScore())
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now())
                .approvedBy(event.getApprovedBy())
                .approvedAt(LocalDateTime.now())
                .isActive(true)
                .aiModel("AutonomousLearningCoordinator")
                .build();

            // AI 진화 정책의 상세 설명에 메타데이터 포함
            String detailedDescription = event.getPolicyDescription() +
                "\n[Evolution Metadata] Original Policy ID: " + event.getPolicyId() +
                ", Confidence: " + event.getConfidenceScore() +
                ", Target System: " + event.getTargetSystem();
            policy.setFriendlyDescription(detailedDescription);

            // 3. PolicyRule과 PolicyTarget 생성 및 연결
            createPolicyRulesAndTargets(policy, policyRules);

            // 4. 정책 저장
            Policy savedPolicy = policyRepository.save(policy);

            // 5. XACML 정책 엔진에 로드
            loadPolicyToXacmlEngine(savedPolicy);

            // 6. 정책 적용 검증
            validatePolicyApplication(savedPolicy);

            log.info("PolicyApprovedEvent processed successfully: created policy ID {} from evolution proposal {}",
                savedPolicy.getId(), event.getPolicyId());

        } catch (Exception e) {
            log.error("Failed to process PolicyApprovedEvent: {}", event, e);
            // 실패 시 롤백 처리는 @Transactional이 자동으로 처리
        }
    }

    /**
     * 정책 규칙 파싱
     */
    private Map<String, Object> parsePolicyRules(String policyRulesJson) {
        try {
            if (policyRulesJson == null || policyRulesJson.trim().isEmpty()) {
                return new HashMap<>();
            }
            return objectMapper.readValue(policyRulesJson, new TypeReference<Map<String, Object>>() {});
        } catch (Exception e) {
            log.error("Failed to parse policy rules JSON: {}", policyRulesJson, e);
            return new HashMap<>();
        }
    }

    /**
     * 정책 규칙 검증
     */
    private boolean validatePolicyRules(Map<String, Object> policyRules) {
        if (policyRules.isEmpty()) {
            log.warn("Empty policy rules detected");
            return false;
        }

        // 필수 필드 검증
        if (!policyRules.containsKey("effect") || !policyRules.containsKey("targets")) {
            log.error("Missing required fields in policy rules: effect or targets");
            return false;
        }

        String effect = (String) policyRules.get("effect");
        if (!"ALLOW".equals(effect) && !"DENY".equals(effect)) {
            log.error("Invalid effect value: {}", effect);
            return false;
        }

        return true;
    }

    /**
     * 규칙에서 Effect 결정
     */
    private Policy.Effect determineEffectFromRules(Map<String, Object> policyRules) {
        String effect = (String) policyRules.getOrDefault("effect", "ALLOW");
        return "DENY".equals(effect) ? Policy.Effect.DENY : Policy.Effect.ALLOW;
    }

    /**
     * 규칙에서 우선순위 결정
     */
    private int determinePriorityFromRules(Map<String, Object> policyRules) {
        Integer priority = (Integer) policyRules.get("priority");
        return priority != null ? priority : 100; // 기본 우선순위
    }

    /**
     * PolicyRule과 PolicyTarget 생성 및 연결
     */
    private void createPolicyRulesAndTargets(Policy policy, Map<String, Object> policyRules) {
        try {
            // PolicyTarget 생성
            @SuppressWarnings("unchecked")
            Map<String, Object> targets = (Map<String, Object>) policyRules.get("targets");
            if (targets != null) {
                for (Map.Entry<String, Object> targetEntry : targets.entrySet()) {
                    PolicyTarget target = PolicyTarget.builder()
                        .targetType(targetEntry.getKey())
                        .targetIdentifier(targetEntry.getValue().toString())
                        .httpMethod("ALL") // 기본값
                        .build();
                    policy.addTarget(target);
                }
            }

            // PolicyRule 생성 (간단한 형태로)
            @SuppressWarnings("unchecked")
            Map<String, Object> rules = (Map<String, Object>) policyRules.getOrDefault("rules", new HashMap<>());
            for (Map.Entry<String, Object> ruleEntry : rules.entrySet()) {
                PolicyRule rule = PolicyRule.builder()
                    .description("AI evolved rule: " + ruleEntry.getKey() + " - " + ruleEntry.getValue().toString())
                    .build();
                policy.addRule(rule);
            }

            // 기본 규칙이 없으면 생성
            if (policy.getRules().isEmpty()) {
                PolicyRule defaultRule = PolicyRule.builder()
                    .description("AI evolved default policy - allows access based on evolution analysis")
                    .build();
                policy.addRule(defaultRule);
            }

        } catch (Exception e) {
            log.error("Failed to create policy rules and targets", e);
        }
    }

    /**
     * XACML 정책 엔진에 정책 로드
     */
    private void loadPolicyToXacmlEngine(Policy policy) {
        try {
            if (policyRetrievalPoint != null) {
                // 정책 캐시 클리어하여 새 정책이 로드되도록 함
                if ("URL".equals(getTargetType(policy))) {
                    policyRetrievalPoint.clearUrlPoliciesCache();
                    log.info("Cleared URL policies cache for policy: {}", policy.getId());
                } else {
                    policyRetrievalPoint.clearMethodPoliciesCache();
                    log.info("Cleared method policies cache for policy: {}", policy.getId());
                }
            } else {
                log.warn("PolicyRetrievalPoint not available - policy will be loaded on next request");
            }
        } catch (Exception e) {
            log.error("Failed to load policy to XACML engine: {}", policy.getId(), e);
        }
    }

    /**
     * 정책 적용 검증
     */
    private void validatePolicyApplication(Policy policy) {
        try {
            // 1. 정책 활성화 상태 확인
            if (!policy.getIsActive()) {
                log.warn("Policy {} is not active after creation", policy.getId());
            }

            // 2. 규칙과 타겟 관계 확인
            if (policy.getRules().isEmpty()) {
                log.error("Policy {} has no rules after creation", policy.getId());
            }

            if (policy.getTargets().isEmpty()) {
                log.warn("Policy {} has no targets after creation", policy.getId());
            }

            // 3. 정책 충돌 검사 (간단한 검사)
            List<Policy> existingPolicies = policyRepository.findAll().stream()
                .filter(p -> p.getName().equals(policy.getName()) && p.getIsActive())
                .toList();
            if (existingPolicies.size() > 1) {
                log.warn("Multiple active policies with same name: {}", policy.getName());
            }

            log.info("Policy validation completed for policy: {}", policy.getId());

        } catch (Exception e) {
            log.error("Policy validation failed for policy: {}", policy.getId(), e);
        }
    }

    /**
     * 정책의 주요 타겟 타입 결정
     */
    private String getTargetType(Policy policy) {
        return policy.getTargets().stream()
            .findFirst()
            .map(PolicyTarget::getTargetType)
            .orElse("METHOD");
    }
}