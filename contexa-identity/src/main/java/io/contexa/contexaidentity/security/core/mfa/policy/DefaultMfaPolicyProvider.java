package io.contexa.contexaidentity.security.core.mfa.policy;

import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.model.MfaDecision;
import io.contexa.contexaidentity.security.core.mfa.policy.evaluator.MfaPolicyEvaluator;
import io.contexa.contexaidentity.security.enums.AuthType;
import io.contexa.contexaidentity.security.properties.AuthContextProperties;
import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.repository.UserRepository;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.lang.Nullable;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.*;
import java.util.stream.Collectors;

/**
 * 완전 일원화된 DefaultMfaPolicyProvider
 * 개선사항:
 * - 이벤트 처리 표준화: 1) 상태 업데이트 2) 저장 3) 이벤트 전송 순서 보장
 * - 예외 처리 강화: 각 단계별 실패 처리 로직 추가
 * - 성능 최적화: 불필요한 동기화 호출 최소화
 */
@Slf4j
@RequiredArgsConstructor
@Component
public class DefaultMfaPolicyProvider implements MfaPolicyProvider {

    protected final UserRepository userRepository;
    protected final ApplicationContext applicationContext;
    protected final AuthContextProperties properties;
    protected final MfaPolicyEvaluator policyEvaluator;
    protected final PlatformConfig platformConfig;
    private AuthenticationFlowConfig cachedMfaFlowConfig;

    /**
     * Phase 2 개선: Bean 초기화 시 MFA FlowConfig를 캐싱 (Blocking 없음)
     * Reactive context에서 synchronized block 제거
     */
    @PostConstruct
    public void initializeMfaFlowConfig() {
        try {
            if (platformConfig != null) {
                cachedMfaFlowConfig = platformConfig.getFlows().stream()
                        .filter(flow -> AuthType.MFA.name().equalsIgnoreCase(flow.getTypeName()))
                        .findFirst()
                        .orElse(null);

                if (cachedMfaFlowConfig != null) {
                    log.info("MFA flow configuration initialized successfully at startup");
                } else {
                    log.warn("No MFA flow configuration found during initialization");
                }
            }
        } catch (Exception e) {
            log.error("Error initializing MFA flow configuration", e);
        }
    }


    /**
     * Phase 2: 초기 MFA 요구사항 평가 (읽기 전용)
     */
    @Override
    public MfaDecision evaluateInitialMfaRequirement(FactorContext ctx) {
        Assert.notNull(ctx, "FactorContext cannot be null.");

        String sessionId = ctx.getMfaSessionId();
        log.debug("Evaluating initial MFA requirement for session: {}", sessionId);

        // 읽기 전용 평가
        MfaDecision decision = evaluatePolicy(ctx);

        log.info("Initial MFA evaluation completed for session: {}, required: {}, blocked: {}",
                sessionId, decision.isRequired(), decision.isBlocked());

        return decision;
    }

    /**
     * MFA 정책을 평가합니다.
     */
    protected MfaDecision evaluatePolicy(FactorContext ctx) {
        // 정책 평가자를 사용하여 평가
        MfaDecision decision = policyEvaluator.evaluatePolicy(ctx);
        
        log.info("MFA policy evaluated for user {}: type={}, required={}, factorCount={}",
                ctx.getUsername(), decision.getType(), decision.isRequired(), decision.getFactorCount());
        
        return decision;
    }

    @Override
    public boolean isFactorAvailableForUser(String username, AuthType factorType, FactorContext ctx) {
        Assert.hasText(username, "Username cannot be empty.");
        Assert.notNull(factorType, "FactorType cannot be null.");

        // P0-2 개선: FactorContext의 availableFactors는 정책 평가 후 검증된 팩터 목록
        // 1. FactorContext에서 확인 (우선순위 1 - 가장 신뢰할 수 있음)
        if (ctx != null) {
            Set<AuthType> availableFactors = ctx.getAvailableFactors();
            if (availableFactors != null && !availableFactors.isEmpty()) {
                boolean available = availableFactors.contains(factorType);
                log.debug("Factor {} availability check from context for user {}: {} (validated by policy evaluation)",
                        factorType, username, available);
                return available;
            }
        }

        // 2. DSL 설정에서 확인 (폴백 - 컨텍스트가 없거나 초기화되지 않은 경우)
        // 주의: DSL에만 의존하면 사용자별 실제 가용성을 보장할 수 없음
        AuthenticationFlowConfig mfaFlowConfig = findMfaFlowConfig();
        if (mfaFlowConfig == null) {
            log.warn("MFA flow config not found. Factor {} not available for user: {}", factorType, username);
            return false;
        }

        Map<AuthType, ?> factorOptions = mfaFlowConfig.getRegisteredFactorOptions();
        if (factorOptions == null || !factorOptions.containsKey(factorType)) {
            log.debug("Factor {} not defined in DSL for user {}", factorType, username);
            return false;
        }

        // DSL에 정의되어 있으면 일단 true 반환 (정책 평가 단계에서 추가 검증됨)
        log.debug("Factor {} available from DSL for user {} (requires policy evaluation for full validation)",
                factorType, username);
        return true;
    }

    @Override
    public Integer getRequiredFactorCount(String userId, String flowType) {
        Users user = userRepository.findByUsernameWithGroupsRolesAndPermissions(userId).orElse(null);

        if (user != null) {
            int baseCount = 1; // 기본값
            return adjustRequiredFactorCount(baseCount, userId, flowType);
        }

        return switch (flowType.toLowerCase()) {
            case "mfa" -> 2;
            case "mfa-stepup" -> 1;
            case "mfa-transactional" -> 1;
            default -> 1;
        };
    }

    // AI 통합을 위한 확장 포인트 (Protected로 오버라이드 가능)
    protected int adjustRequiredFactorCount(int baseCount, String userId, String flowType) {
        // 기본 구현은 그대로 반환
        return baseCount;
    }

    private List<AuthenticationStepConfig> getRequiredSteps(AuthenticationFlowConfig flowConfig) {
        return flowConfig.getStepConfigs().stream()
                .filter(AuthenticationStepConfig::isRequired)
                .collect(Collectors.toList());
    }

    private CompletionStatus evaluateCompletionStatus(FactorContext ctx,
                                                      List<AuthenticationStepConfig> requiredSteps) {
        Set<String> completedRequiredStepIds = new HashSet<>();
        List<String> missingRequiredStepIds = new ArrayList<>();

        for (AuthenticationStepConfig requiredStep : requiredSteps) {

            if(requiredStep.isPrimary()) continue; // 1차 인증은 제외

            String requiredStepId = requiredStep.getStepId();

            if (!StringUtils.hasText(requiredStepId)) {
                log.error("Required step with missing or empty stepId found");
                continue;
            }

            if (isStepCompleted(ctx, requiredStepId)) {
                completedRequiredStepIds.add(requiredStepId);
            } else {
                missingRequiredStepIds.add(requiredStepId);
            }
        }

        boolean allRequiredCompleted = missingRequiredStepIds.isEmpty();
        return new CompletionStatus(allRequiredCompleted, missingRequiredStepIds);
    }

    private boolean isStepCompleted(FactorContext ctx, String stepId) {
        return ctx.getCompletedFactors().stream()
                .anyMatch(completedFactor -> stepId.equals(completedFactor.getStepId()));
    }

    private Optional<AuthenticationStepConfig> findNextStepConfig(
            AuthenticationFlowConfig flowConfig, AuthType factorType, FactorContext ctx) {
        return flowConfig.getStepConfigs().stream()
                .filter(step -> factorType.name().equalsIgnoreCase(step.getType()) &&
                        !ctx.isFactorCompleted(step.getStepId()))
                .min(Comparator.comparingInt(AuthenticationStepConfig::getOrder));
    }

    @Nullable
    private AuthType determineNextFactorInternal(List<AuthType> availableFactors,
                                                 List<AuthenticationStepConfig> completedFactorSteps,
                                                 List<AuthenticationStepConfig> flowSteps) {
        if (CollectionUtils.isEmpty(availableFactors) || CollectionUtils.isEmpty(flowSteps)) {
            return null;
        }

        Set<String> completedStepIds = completedFactorSteps.stream()
                .map(AuthenticationStepConfig::getStepId)
                .collect(Collectors.toSet());

        // DSL 등록 순서 (availableFactors)를 우선 사용
        for (AuthType factor : availableFactors) {
            // 해당 팩터의 미완료 Step 찾기
            Optional<AuthenticationStepConfig> nextStep = flowSteps.stream()
                    .filter(step -> factor.name().equalsIgnoreCase(step.getType()))
                    .filter(step -> !completedStepIds.contains(step.getStepId()))
                    .min(Comparator.comparingInt(AuthenticationStepConfig::getOrder));

            if (nextStep.isPresent()) {
                log.debug("Next MFA factor determined by DSL order: {} (StepId: {})",
                        factor, nextStep.get().getStepId());
                return factor;
            }
        }

        log.debug("No more MFA factors to process based on policy.");
        return null;
    }

    @Nullable
    private AuthType parseAuthType(String type) {
        try {
            return AuthType.valueOf(type.toUpperCase());
        } catch (IllegalArgumentException e) {
            log.warn("Invalid AuthType: {}", type);
            return null;
        }
    }

    public List<AuthType> getAvailableMfaFactorsForUser(String username) {
        if (!StringUtils.hasText(username)) {
            return Collections.emptyList();
        }

        // DSL 기반으로 전환 - AuthenticationFlowConfig에서 팩터 조회
        AuthenticationFlowConfig mfaFlowConfig = findMfaFlowConfig();
        if (mfaFlowConfig != null) {
            Map<AuthType, ?> factorOptions = mfaFlowConfig.getRegisteredFactorOptions();
            if (factorOptions != null) {
                return new ArrayList<>(factorOptions.keySet());
            }
        }

        log.debug("No DSL-defined factors found for user: {}", username);
        return Collections.emptyList();
    }

    /**
     * Phase 2 개선: MFA FlowConfig 조회 (Blocking 제거)
     * @PostConstruct에서 초기화된 캐시만 반환
     */
    @Nullable
    private AuthenticationFlowConfig findMfaFlowConfig() {
        return cachedMfaFlowConfig;
    }

    /**
     * 설정 변경 시 캐시 무효화 (Phase 2 개선: synchronized 제거)
     */
    public void invalidateFlowConfigCache() {
        cachedMfaFlowConfig = null;
        log.info("MFA flow configuration cache invalidated. Re-initializing...");
        initializeMfaFlowConfig();
    }

    private HttpServletRequest getCurrentRequest() {
        ServletRequestAttributes attrs = (ServletRequestAttributes)
                RequestContextHolder.getRequestAttributes();
        return attrs != null ? attrs.getRequest() : null;
    }

    // ============================================================
    // Phase 2: 읽기 전용 평가 메서드 (Single Source of Truth 패턴)
    // ============================================================

    /**
     * Phase 2: 다음 팩터 평가 (읽기 전용)
     * Context를 수정하지 않고 결정만 반환
     */
    @Override
    public NextFactorDecision evaluateNextFactor(FactorContext ctx) {
        Assert.notNull(ctx, "FactorContext cannot be null.");

        AuthenticationFlowConfig mfaFlowConfig = findMfaFlowConfig();
        if (mfaFlowConfig == null) {
            log.error("MFA flow configuration not found");
            return NextFactorDecision.error("MFA flow configuration not found");
        }

        Set<AuthType> availableFactors = ctx.getAvailableFactors();
        if (availableFactors == null || availableFactors.isEmpty()) {
            log.warn("No available factors, all factors may be completed");
            return NextFactorDecision.noMoreFactors();
        }

        List<AuthType> factorsForProcessing = new ArrayList<>(availableFactors);

        AuthType nextFactorType = determineNextFactorInternal(
                factorsForProcessing,
                ctx.getCompletedFactors(),
                mfaFlowConfig.getStepConfigs()
        );

        if (nextFactorType != null) {
            Optional<AuthenticationStepConfig> nextStepConfigOpt =
                    findNextStepConfig(mfaFlowConfig, nextFactorType, ctx);

            if (nextStepConfigOpt.isPresent()) {
                AuthenticationStepConfig nextStep = nextStepConfigOpt.get();
                log.info("Next factor evaluated: {} (StepId: {})", nextFactorType, nextStep.getStepId());
                return NextFactorDecision.nextFactor(nextFactorType, nextStep.getStepId());
            }
        }

        log.info("No more factors to process");
        return NextFactorDecision.noMoreFactors();
    }

    /**
     * Phase 2: 완료 여부 평가 (읽기 전용)
     * Context를 수정하지 않고 결정만 반환
     */
    @Override
    public CompletionDecision evaluateCompletion(FactorContext ctx,
                                                 AuthenticationFlowConfig mfaFlowConfig) {
        Assert.notNull(ctx, "FactorContext cannot be null");
        Assert.notNull(mfaFlowConfig, "AuthenticationFlowConfig cannot be null");

        if (!AuthType.MFA.name().equalsIgnoreCase(mfaFlowConfig.getTypeName())) {
            log.warn("checkCompletion called with non-MFA flow config");
            return CompletionDecision.error("Non-MFA flow configuration");
        }

        List<AuthenticationStepConfig> requiredSteps = getRequiredSteps(mfaFlowConfig);

        if (requiredSteps.isEmpty()) {
            log.info("No required steps, marking as completed");
            return CompletionDecision.completed();
        }

        CompletionStatus status = evaluateCompletionStatus(ctx, requiredSteps);

        if (status.allRequiredCompleted && !ctx.getCompletedFactors().isEmpty()) {
            log.info("All required factors completed");
            return CompletionDecision.completed();
        }

        if (!ctx.getAvailableFactors().isEmpty() && ctx.getCompletedFactors().isEmpty()) {
            Integer selectFactorAttempts = (Integer) ctx.getAttribute("selectFactorAttemptCount");
            int attemptCount = (selectFactorAttempts == null) ? 1 : selectFactorAttempts + 1;

            if (attemptCount > 3) {
                log.error("Maximum factor selection attempts exceeded");
                return CompletionDecision.error("Maximum factor selection attempts exceeded");
            }

            log.info("Needs factor selection (attempt {})", attemptCount);
            return CompletionDecision.needsFactorSelection(attemptCount);
        }

        if (ctx.getAvailableFactors().isEmpty()) {
            log.error("No available MFA factors");
            return CompletionDecision.error("No available MFA factors defined");
        }

        log.info("Not all required factors completed. Missing: {}", status.missingRequiredStepIds);
        return CompletionDecision.incomplete(status.missingRequiredStepIds);
    }

    // ============================================================
    // 내부 클래스
    // ============================================================

    private static class CompletionStatus {
        final boolean allRequiredCompleted;
        final List<String> missingRequiredStepIds;

        CompletionStatus(boolean allRequiredCompleted, List<String> missingRequiredStepIds) {
            this.allRequiredCompleted = allRequiredCompleted;
            this.missingRequiredStepIds = missingRequiredStepIds;
        }
    }
}
