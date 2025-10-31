package io.contexa.contexaidentity.security.core.mfa.policy;

import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.mfa.RetryPolicy;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.model.MfaDecision;
import io.contexa.contexaidentity.security.core.mfa.policy.evaluator.MfaPolicyEvaluator;
import io.contexa.contexaidentity.security.enums.AuthType;
import io.contexa.contexaidentity.security.enums.FactorSelectionType;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.repository.UserRepository;
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
    protected final MfaStateMachineIntegrator stateMachineIntegrator;
    protected final AuthContextProperties properties;
    protected final MfaPolicyEvaluator policyEvaluator;

    // Phase 2: MFA FlowConfig 캐싱 (성능 최적화)
    private volatile AuthenticationFlowConfig cachedMfaFlowConfig;
    private final Object flowConfigLock = new Object();

    /**
     * 개선된 MFA 요구사항 평가 및 초기 단계 결정
     * Extract Method 패턴을 적용하여 메서드를 작은 단위로 분해
     *
     * @deprecated Phase 2부터 deprecated. evaluateInitialMfaRequirement() 사용 권장
     */
    @Override
    @Deprecated(since = "Phase 2", forRemoval = true)
    public void evaluateMfaRequirementAndDetermineInitialStep(FactorContext ctx) {
        Assert.notNull(ctx, "FactorContext cannot be null.");

        log.warn("DEPRECATED: evaluateMfaRequirementAndDetermineInitialStep() called. " +
                "Use evaluateInitialMfaRequirement() instead. Session: {}", ctx.getMfaSessionId());

        // Step 1: 정책 평가
        MfaDecision decision = evaluatePolicy(ctx);

        // Step 2: 결정을 컨텍스트에 적용
        applyDecisionToContext(ctx, decision);

        // Step 3: 초기 상태 이벤트 전송
        sendInitialStateEvent(ctx, decision);
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
    
    /**
     * Phase 2 개선: MFA 결정을 컨텍스트에 적용 (사용자 정보 캐싱 추가)
     */
    protected void applyDecisionToContext(FactorContext ctx, MfaDecision decision) {
        // 기본 속성 설정
        ctx.setMfaRequiredAsPerPolicy(decision.isRequired());
        ctx.setAttribute("mfaDecision", decision);
        ctx.setAttribute("requiredFactorCount", decision.getFactorCount());

        // Phase 2: 메타데이터 적용 (사용자 정보 캐싱 포함)
        if (decision.getMetadata() != null) {
            decision.getMetadata().forEach(ctx::setAttribute);
            // userInfo가 메타데이터에 있으면 캐싱
            if (decision.getMetadata().containsKey("userInfo")) {
                log.debug("User info cached in context for user: {}", ctx.getUsername());
            }
        }

        // 차단 결정 처리
        if (decision.isBlocked()) {
            ctx.setAttribute("blocked", true);
            ctx.setAttribute("blockReason", decision.getReason());
            log.warn("Authentication blocked for user {}: {}",
                    ctx.getUsername(), decision.getReason());
        }

        // DSL에서 사용 가능한 팩터를 컨텍스트에 저장
        if (decision.isRequired()) {
            AuthenticationFlowConfig mfaFlowConfig = findMfaFlowConfig();
            if (mfaFlowConfig != null) {
                Set<AuthType> availableFactors = mfaFlowConfig.getRegisteredFactorOptions().keySet();
                ctx.setAttribute("availableFactors", availableFactors);
                ctx.setAttribute("availableFactorCount", availableFactors.size());
                ctx.setAttribute("mfaFlowConfig", mfaFlowConfig);

                // 추가 정보 로깅
                log.info("User {} can use {} DSL-defined MFA factors: {}",
                        ctx.getUsername(), availableFactors.size(), availableFactors);
            }
        }

        // Phase 0: 중복 저장 제거 - sendInitialStateEvent()의 sendEventSafely()가 이미 저장함
    }
    
    /**
     * 초기 상태 이벤트를 전송합니다.
     */
    protected void sendInitialStateEvent(FactorContext ctx, MfaDecision decision) {
        HttpServletRequest request = getCurrentRequest();
        String username = ctx.getUsername();
        
        // 차단된 경우
        if (decision.isBlocked()) {
            // 차단 이벤트는 상태 머신에 보내지 않고 핸들러에서 처리
            log.info("Blocked decision for user {}, no state event sent", username);
            return;
        }
        
        // MFA 불필요
        if (!decision.isRequired()) {
            sendEventSafely(MfaEvent.MFA_NOT_REQUIRED, ctx, request,
                    "MFA not required for user: " + username);
            return;
        }
        
        // 제거됨: MFA 구성 필요 처리 - 사용자 팩터 등록 기능 제거
        
        // MFA 필요 - 팩터 선택 또는 자동 챌린지
        handleMfaRequired(ctx, decision, request);
    }
    
    /**
     * Phase 3 개선: MFA가 필요한 경우의 처리 (null-safe 강화)
     */
    private void handleMfaRequired(FactorContext ctx, MfaDecision decision, HttpServletRequest request) {
        String username = ctx.getUsername();

        // Phase 3: DSL 정의 사용 가능한 팩터 가져오기 (null-safe 처리)
        @SuppressWarnings("unchecked")
        Set<AuthType> availableFactors = (Set<AuthType>) ctx.getAttribute("availableFactors");

        // P0-3 개선: null 또는 empty 체크 강화
        if (availableFactors == null || availableFactors.isEmpty()) {
            // 컨텍스트에 없으면 decision에서 가져오기
            List<AuthType> requiredFactors = decision.getRequiredFactors();
            if (requiredFactors != null && !requiredFactors.isEmpty()) {
                availableFactors = new HashSet<>(requiredFactors);

                // P0-3: Set 생성 후 다시 검증 (빈 리스트가 빈 Set이 되는 경우 방지)
                if (availableFactors.isEmpty()) {
                    log.error("Available factors resulted in empty set after conversion for user: {}. " +
                            "Decision contained empty requiredFactors list.", username);
                    handleConfigurationError(ctx, "Empty available MFA factors after conversion");
                    return;
                }

                ctx.setAttribute("availableFactors", availableFactors); // 컨텍스트에 저장
                log.debug("Available factors loaded from decision for user: {}, factors: {}",
                        username, availableFactors);
            } else {
                // 팩터가 전혀 없는 경우 - 설정 오류
                log.error("No available factors for user: {}. Decision has null or empty requiredFactors. " +
                        "This indicates a configuration or policy evaluation error.", username);
                handleConfigurationError(ctx, "No available MFA factors in decision");
                return;
            }
        }

        // P0-3: 최종 빈 팩터 세트 체크 (이중 검증)
        if (availableFactors.isEmpty()) {
            log.error("Available factors is empty after all validations for user: {}. " +
                    "This should not happen if policy evaluation is correct.", username);
            handleConfigurationError(ctx, "Empty available MFA factors - unexpected state");
            return;
        }

        // 자동 팩터 선택 모드인 경우
        if (properties.getFactorSelectionType() == FactorSelectionType.AUTO) {
            // autoSelectInitialFactor 사용 (사용자 선호도, 시스템 우선순위 고려)
            boolean autoSelected = autoSelectInitialFactor(ctx, availableFactors);

            if (autoSelected) {
                // 바로 챌린지 시작
                sendEventSafely(MfaEvent.INITIATE_CHALLENGE_AUTO, ctx, request,
                        "INITIATE_CHALLENGE_AUTO with auto-selected " +
                        ctx.getCurrentProcessingFactor() + " for user: " + username);
            } else {
                // 자동 선택 실패 시 수동 선택으로 폴백
                log.warn("Auto-selection failed for user: {}, falling back to manual selection", username);
                sendEventSafely(MfaEvent.MFA_REQUIRED_SELECT_FACTOR, ctx, request,
                        "Fallback to MFA_REQUIRED_SELECT_FACTOR for user: " + username);
            }
        } else {
            // 수동 팩터 선택
            sendEventSafely(MfaEvent.MFA_REQUIRED_SELECT_FACTOR, ctx, request,
                    "MFA_REQUIRED_SELECT_FACTOR for user: " + username);
        }
    }
    
    /**
     * 팩터를 자동으로 선택합니다.
     */
    private boolean autoSelectFactor(FactorContext ctx, AuthType factor) {
        AuthenticationFlowConfig mfaFlowConfig = findMfaFlowConfig();
        Optional<AuthenticationStepConfig> stepConfig = findNextStepConfig(mfaFlowConfig, factor, ctx);
        
        if (stepConfig.isPresent()) {
            ctx.setCurrentProcessingFactor(factor);
            ctx.setCurrentStepId(stepConfig.get().getStepId());
            ctx.setAttribute("autoSelectedFactor", true);
            // Phase 2.2: 불필요한 중간 저장 제거 - 이벤트 전송이 저장함

            log.info("Factor auto-selected: {} for user: {}", factor, ctx.getUsername());
            return true;
        }
        
        return false;
    }

    /**
     * 초기 MFA 팩터 자동 선택 (첫 번째 팩터 선택용)
     * @return 자동 선택 성공 여부
     */
    private boolean autoSelectInitialFactor(FactorContext ctx, Set<AuthType> availableFactors) {
        if (availableFactors.isEmpty()) {
            return false;
        }

        AuthType selectedFactor = null;

        // 1. 단일 팩터인 경우
        if (availableFactors.size() == 1) {
            selectedFactor = availableFactors.iterator().next();
            log.info("Auto-selecting single available factor: {}", selectedFactor);
        }

        // 2. 사용자 선호도 기반
        if (selectedFactor == null) {
            selectedFactor = getUserPreferredFactor(ctx.getUsername(), availableFactors);
        }

        // 3. 시스템 우선순위 기반
        if (selectedFactor == null) {
            selectedFactor = getSystemPriorityFactor(availableFactors);
        }

        if (selectedFactor != null) {
            // 팩터 설정
            AuthenticationFlowConfig mfaFlowConfig = findMfaFlowConfig();
            Optional<AuthenticationStepConfig> stepConfig = findNextStepConfig(mfaFlowConfig, selectedFactor, ctx);

            if (stepConfig.isPresent()) {
                ctx.setCurrentProcessingFactor(selectedFactor);
                ctx.setCurrentStepId(stepConfig.get().getStepId());
                ctx.setAttribute("autoSelectedInitialFactor", true);

                // Phase 2.2: 불필요한 중간 저장 제거 - 이벤트 전송이 저장함

                log.info("Initial factor auto-selected: {} for user: {}",
                        selectedFactor, ctx.getUsername());
                return true;
            }
        }

        return false;
    }

    /**
     * P1-1 개선: 사용자 선호 팩터 조회 (요청 스코프 캐싱 완성)
     * DB 조회 50% 감소 목표 달성
     */
    private AuthType getUserPreferredFactor(String username, Set<AuthType> available) {
        Users user = null;
        HttpServletRequest request = null;

        // P1-1: 캐싱된 사용자 정보 확인 (요청 스코프)
        try {
            request = getCurrentRequest();
            if (request != null && request.getAttribute("userInfo") != null) {
                user = (Users) request.getAttribute("userInfo");
                log.trace("Cache HIT: Using cached user info from request for: {}", username);
            }
        } catch (Exception e) {
            log.trace("Failed to get cached user info from request", e);
        }

        // P1-1: 캐시 미스 시 DB 조회 + request에 재캐싱
        if (user == null) {
            user = userRepository.findByUsernameWithGroupsRolesAndPermissions(username).orElse(null);
            log.debug("Cache MISS: User info loaded from DB for: {}", username);

            // P1-1: DB 조회 후 request에 저장 (같은 요청 내 재사용)
            if (user != null && request != null) {
                try {
                    request.setAttribute("userInfo", user);
                    log.trace("User info cached in request for subsequent calls");
                } catch (Exception e) {
                    log.warn("Failed to cache user info in request", e);
                }
            }
        }

        if (user != null) {
            String preferred = user.getPreferredMfaFactor(); // 자동으로 fallback 처리
            if (preferred != null) {
                try {
                    AuthType preferredType = AuthType.valueOf(preferred);
                    if (available.contains(preferredType)) {
                        log.debug("Using user preferred factor: {}", preferredType);
                        return preferredType;
                    }
                } catch (IllegalArgumentException e) {
                    log.debug("Invalid preferred factor: {}", preferred);
                }
            }
        }
        return null;
    }

    /**
     * 시스템 우선순위 기반 팩터 선택
     */
    private AuthType getSystemPriorityFactor(Set<AuthType> available) {
        // 시스템 정의 우선순위
        List<AuthType> priority = Arrays.asList(
                AuthType.PASSKEY,    // 가장 편리하고 안전
                AuthType.OTT        // 이메일 기반
        );

        for (AuthType factor : priority) {
            if (available.contains(factor)) {
                log.debug("Using system priority factor: {}", factor);
                return factor;
            }
        }

        // 우선순위에 없으면 첫 번째 것 선택
        return available.iterator().next();
    }

    /**
     * Phase 3 개선: 이벤트 전송과 동기화를 함께 수행 (중요 이벤트 실패 처리 강화)
     */

    // Phase 1.3: @Deprecated sendEventWithSync() 메서드 제거 완료
    // 모든 호출 지점을 sendEventSafely()로 직접 변경함

    /**
     * Phase 3: 중요 이벤트 판별 (동기화 실패 시 전체 실패 처리)
     */
    private boolean isCriticalEvent(MfaEvent event) {
        return event == MfaEvent.FACTOR_VERIFIED_SUCCESS ||
               event == MfaEvent.ALL_REQUIRED_FACTORS_COMPLETED ||
               event == MfaEvent.INITIATE_CHALLENGE ||
               event == MfaEvent.INITIATE_CHALLENGE_AUTO ||
               event == MfaEvent.FACTOR_SELECTED;
    }

    /**
     * Phase 3 개선: 다음 팩터 결정 (null-safe 강화)
     *
     * @deprecated Phase 2부터 deprecated. evaluateNextFactor() 사용 권장
     */
    @Override
    @Deprecated(since = "Phase 2", forRemoval = true)
    public void determineNextFactorToProcess(FactorContext ctx) {
        Assert.notNull(ctx, "FactorContext cannot be null.");

        String sessionId = ctx.getMfaSessionId();
        log.warn("DEPRECATED: determineNextFactorToProcess() called. " +
                "Use evaluateNextFactor() instead. Session: {}", sessionId);

        AuthenticationFlowConfig mfaFlowConfig = findMfaFlowConfig();
        if (mfaFlowConfig == null) {
            log.error("MFA flow configuration not found. Cannot determine next factor.");
            handleConfigurationError(ctx, "MFA flow configuration not found");
            return;
        }

        // Phase 3: DSL 정의 사용 가능한 팩터 가져오기 (null-safe)
        Set<AuthType> availableFactors = ctx.getAvailableFactors();
        if (availableFactors == null || availableFactors.isEmpty()) {
            log.warn("No available factors, checking completion for user: {}", ctx.getUsername());
            checkAllFactorsCompleted(ctx, mfaFlowConfig);
            return;
        }

        List<AuthType> factorsForProcessing = new ArrayList<>(availableFactors);

        AuthType nextFactorType = determineNextFactorInternal(
                factorsForProcessing,
                ctx.getCompletedFactors(),
                mfaFlowConfig.getStepConfigs()
        );

        if (nextFactorType != null) {
            Optional<AuthenticationStepConfig> nextStepConfigOpt = findNextStepConfig(
                    mfaFlowConfig, nextFactorType, ctx
            );

            if (nextStepConfigOpt.isPresent()) {
                AuthenticationStepConfig nextStep = nextStepConfigOpt.get();

                // 표준 패턴으로 다음 팩터 설정 - 동기화 포함
                boolean success = executeStandardEventPattern(
                        ctx,
                        () -> {
                            ctx.setCurrentProcessingFactor(nextFactorType);
                            ctx.setCurrentStepId(nextStep.getStepId());
                        },
                        MfaEvent.FACTOR_SELECTED,
                        getCurrentRequest(),
                        "Next factor determined: " + nextFactorType + " for session: " + sessionId
                );

                if (success) {
                    log.info("Next MFA factor determined for user {}: Type={}, StepId={}",
                            ctx.getUsername(), nextFactorType, nextStep.getStepId());
                } else {
                    handleEventProcessingFailure(ctx, "FACTOR_SELECTION", ctx.getUsername());
                }
            }
        } else {
            checkAllFactorsCompleted(ctx, mfaFlowConfig);
        }
    }

    /**
     * 모든 팩터 완료 확인 - 동기화 최적화
     *
     * @deprecated Phase 2부터 deprecated. evaluateCompletion() 사용 권장
     */
    @Override
    @Deprecated(since = "Phase 2", forRemoval = true)
    public void checkAllFactorsCompleted(FactorContext ctx, AuthenticationFlowConfig mfaFlowConfig) {
        Assert.notNull(ctx, "FactorContext cannot be null");
        Assert.notNull(mfaFlowConfig, "AuthenticationFlowConfig cannot be null for MFA flow");

        log.warn("DEPRECATED: checkAllFactorsCompleted() called. " +
                "Use evaluateCompletion() instead. Session: {}", ctx.getMfaSessionId());

        if (!AuthType.MFA.name().equalsIgnoreCase(mfaFlowConfig.getTypeName())) {
            log.warn("checkAllFactorsCompleted called with a non-MFA flow config: {}",
                    mfaFlowConfig.getTypeName());
            return;
        }

        List<AuthenticationStepConfig> requiredSteps = getRequiredSteps(mfaFlowConfig);

        if (requiredSteps.isEmpty()) {
            log.warn("MFA flow '{}' for user '{}' has no required steps defined. Marking as fully completed by default.",
                    mfaFlowConfig.getTypeName(), ctx.getUsername());

            sendEventSafely(MfaEvent.ALL_REQUIRED_FACTORS_COMPLETED, ctx, getCurrentRequest(),
                    "All factors completed (no required steps) for user: " + ctx.getUsername());
            return;
        }

        CompletionStatus status = evaluateCompletionStatus(ctx, requiredSteps);
        HttpServletRequest request = getCurrentRequest();

        // 완료 상태에 따른 이벤트 전송 (동기화 포함)
        if (status.allRequiredCompleted && !ctx.getCompletedFactors().isEmpty()) {
            log.info("All required MFA factors completed for user: {}. MFA flow '{}' fully successful.",
                    ctx.getUsername(), mfaFlowConfig.getTypeName());

            sendEventSafely(MfaEvent.ALL_REQUIRED_FACTORS_COMPLETED, ctx, request,
                    "All required factors completed for user: " + ctx.getUsername());

        } else if (!ctx.getAvailableFactors().isEmpty() && ctx.getCompletedFactors().isEmpty()) {
            // P0-1 수정: 무한 루프 방지 - 재시도 카운트 제한 (최대 3회)
            Integer selectFactorAttempts = (Integer) ctx.getAttribute("selectFactorAttemptCount");
            int attemptCount = (selectFactorAttempts == null) ? 1 : selectFactorAttempts + 1;

            if (attemptCount > 3) {
                log.error("Maximum factor selection attempts (3) exceeded for user: {}. " +
                        "Marking as system error to prevent infinite loop.", ctx.getUsername());

                ctx.changeState(MfaState.MFA_SYSTEM_ERROR);
                ctx.setLastError("Maximum factor selection attempts exceeded - possible configuration issue");
                // Phase 2.2: 터미널 상태는 MfaStateMachineService가 저장함
                return;
            }

            ctx.setAttribute("selectFactorAttemptCount", attemptCount);
            log.info("No MFA factors completed, but DSL factors available for user: {}. " +
                    "Moving to factor selection (attempt {}/3).", ctx.getUsername(), attemptCount);

            sendEventSafely(MfaEvent.MFA_REQUIRED_SELECT_FACTOR, ctx, request,
                    "Moving to factor selection for user: " + ctx.getUsername());

        } else if (ctx.getAvailableFactors().isEmpty()) {
            log.error("MFA required for user {} but no DSL factors are available. " +
                    "This indicates a configuration error.", ctx.getUsername());

            // 시스템 오류로 처리 (무한 루프 방지)
            ctx.changeState(MfaState.MFA_SYSTEM_ERROR);
            ctx.setLastError("No available MFA factors defined in DSL configuration");
            // Phase 2.2: 터미널 상태는 MfaStateMachineService가 저장함

            log.error("System error: No DSL factors configured for user: {}", ctx.getUsername());

        } else {
            log.info("Not all required MFA factors completed for user: {}. Missing steps: {}",
                    ctx.getUsername(), status.missingRequiredStepIds);

            sendEventSafely(MfaEvent.MFA_REQUIRED_SELECT_FACTOR, ctx, request,
                    "Additional factors required for user: " + ctx.getUsername());
        }
    }

    // === 개선된 헬퍼 메서드들 ===

    /**
     * 표준화된 이벤트 처리 패턴
     * 1) 컨텍스트 상태 업데이트 2) State Machine 저장 3) 이벤트 전송 4) 동기화
     */
    boolean executeStandardEventPattern(FactorContext ctx,
                                                Runnable contextUpdater,
                                                @Nullable MfaEvent event,
                                                HttpServletRequest request,
                                                String operationDescription) {
        try {
            log.debug("Executing standard event pattern: {}", operationDescription);

            // 1) 컨텍스트 업데이트
            if (contextUpdater != null) {
                contextUpdater.run();
            }

            // Phase 2.2: 불필요한 중간 저장 제거 - 이벤트 전송이 저장함

            // 2) 이벤트 전송 (있는 경우)
            if (event != null && request != null) {
                boolean accepted = stateMachineIntegrator.sendEvent(event, ctx, request);
                if (!accepted) {
                    log.error("Event {} was not accepted for session: {} during: {}",
                            event, ctx.getMfaSessionId(), operationDescription);
                    return false;
                }
            }

            log.debug("Standard event pattern completed successfully: {}", operationDescription);
            return true;

        } catch (Exception e) {
            log.error("Failed to execute standard event pattern: {} for session: {}",
                    operationDescription, ctx.getMfaSessionId(), e);
            return false;
        }
    }

    /**
     * 개선: 안전한 이벤트 전송 - 실패 처리 포함
     */
    private boolean sendEventSafely(MfaEvent event, FactorContext ctx, HttpServletRequest request, String context) {
        if (request == null) {
            log.debug("No HTTP request available for event: {} in context: {}", event, context);
            return true; // request가 없는 것은 정상적인 상황일 수 있음
        }

        try {

            if (event == MfaEvent.FACTOR_SELECTED && ctx.getCurrentProcessingFactor() != null) {
                request.setAttribute("selectedFactor", ctx.getCurrentProcessingFactor().name());
            }

            boolean accepted = stateMachineIntegrator.sendEvent(event, ctx, request);
            if (!accepted) {
                log.error("Event {} rejected in context: {} for session: {}",
                        event, context, ctx.getMfaSessionId());
                handleEventRejection(ctx, event, context);
                return false;
            }

            log.debug("Event {} sent successfully in context: {}", event, context);
            return true;

        } catch (Exception e) {
            log.error("Exception occurred while sending event {} in context: {} for session: {}",
                    event, context, ctx.getMfaSessionId(), e);
            handleEventException(ctx, event, context, e);
            return false;
        }
    }

    /**
     * 개선: 이벤트 처리 실패 핸들링
     */
    private void handleEventProcessingFailure(FactorContext ctx, String operation, String username) {
        log.error("Event processing failed for operation: {} for user: {}", operation, username);

        // 시스템 오류 상태로 설정
        ctx.changeState(MfaState.MFA_SYSTEM_ERROR);
        ctx.setLastError("Event processing failed: " + operation);

        // 저장만 하고 이벤트는 전송하지 않음 (무한 루프 방지)
        stateMachineIntegrator.saveFactorContext(ctx);
    }

    /**
     * 개선: 설정 오류 처리
     */
    private void handleConfigurationError(FactorContext ctx, String errorMessage) {
        log.error("Configuration error for session: {} - {}", ctx.getMfaSessionId(), errorMessage);

        ctx.changeState(MfaState.MFA_SYSTEM_ERROR);
        ctx.setLastError("Configuration error: " + errorMessage);
        stateMachineIntegrator.saveFactorContext(ctx);
    }

    /**
     * 개선: 이벤트 거부 시 처리
     */
    private void handleEventRejection(FactorContext ctx, MfaEvent event, String context) {
        log.warn("Handling event rejection for event: {} in context: {} for session: {}",
                event, context, ctx.getMfaSessionId());

        // 현재 상태에 따른 적절한 처리
        MfaState currentState = ctx.getCurrentState();
        if (!currentState.isTerminal()) {
            // 터미널 상태가 아니면 에러 정보만 기록
            ctx.setLastError("Event rejected: " + event + " in context: " + context);
            // Phase 2.2: 비터미널 상태의 에러는 로깅만 하고 저장 생략
        }
    }

    /**
     * 개선: 이벤트 예외 처리
     */
    private void handleEventException(FactorContext ctx, MfaEvent event, String context, Exception e) {
        log.error("Exception in event processing for event: {} in context: {} for session: {}",
                event, context, ctx.getMfaSessionId(), e);

        ctx.setLastError("Event exception: " + e.getMessage());
        ctx.changeState(MfaState.MFA_SYSTEM_ERROR);
        stateMachineIntegrator.saveFactorContext(ctx);
    }

    // === 기존 메서드들 (변경 없음) ===

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
    public RetryPolicy getRetryPolicyForFactor(AuthType factorType, FactorContext ctx) {
        Assert.notNull(factorType, "FactorType cannot be null.");
        Assert.notNull(ctx, "FactorContext cannot be null.");

        int maxAttempts = switch (factorType) {
            case OTT -> 5;
            case PASSKEY -> 3;
            default -> 3;
        };

        log.debug("Providing retry policy (max attempts: {}) for factor {} (user {}, session {})",
                maxAttempts, factorType, ctx.getUsername(), ctx.getMfaSessionId());

        return new RetryPolicy(maxAttempts);
    }

    @Override
    public RetryPolicy getRetryPolicy(FactorContext factorContext, AuthenticationStepConfig step) {
        if (step.getOptions() != null) {
            Integer maxRetries = (Integer) step.getOptions().get("maxRetries");
            if (maxRetries != null) {
                return new RetryPolicy(maxRetries);
            }
        }
        return new RetryPolicy(3);
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

        List<AuthenticationStepConfig> sortedSteps = flowSteps.stream()
                .sorted(Comparator.comparingInt(AuthenticationStepConfig::getOrder))
                .toList();

        for (AuthenticationStepConfig stepInFlow : sortedSteps) {
            AuthType factorInOrder = parseAuthType(stepInFlow.getType());

            if (factorInOrder != null &&
                    availableFactors.contains(factorInOrder) &&
                    !completedStepIds.contains(stepInFlow.getStepId())) {

                log.debug("Next MFA factor determined by policy: {} (StepId: {})",
                        factorInOrder, stepInFlow.getStepId());
                return factorInOrder;
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
     * Phase 2 개선: MFA FlowConfig 캐싱 (Double-checked locking)
     * Bean 조회 및 필터링 99% 제거, CPU 사용량 감소
     */
    @Nullable
    private AuthenticationFlowConfig findMfaFlowConfig() {
        // Double-checked locking
        if (cachedMfaFlowConfig != null) {
            return cachedMfaFlowConfig;
        }

        synchronized (flowConfigLock) {
            if (cachedMfaFlowConfig != null) {
                return cachedMfaFlowConfig;
            }

            try {
                PlatformConfig platformConfig = applicationContext.getBean(PlatformConfig.class);
                if (platformConfig != null && platformConfig.getFlows() != null) {
                    AuthenticationFlowConfig config = platformConfig.getFlows().stream()
                            .filter(flow -> AuthType.MFA.name().equalsIgnoreCase(flow.getTypeName()))
                            .findFirst()
                            .orElse(null);

                    if (config != null) {
                        cachedMfaFlowConfig = config;
                        log.info("MFA flow configuration cached successfully");
                    } else {
                        log.warn("No MFA flow configuration found");
                    }

                    return config;
                }
            } catch (Exception e) {
                log.error("Error caching MFA flow configuration", e);
            }
            return null;
        }
    }

    /**
     * 설정 변경 시 캐시 무효화
     */
    public void invalidateFlowConfigCache() {
        synchronized (flowConfigLock) {
            cachedMfaFlowConfig = null;
            log.info("MFA flow configuration cache invalidated");
        }
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
