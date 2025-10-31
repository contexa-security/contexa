package io.contexa.contexaidentity.security.statemachine.action;

import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.model.MfaDecision;
import io.contexa.contexaidentity.security.enums.AuthType;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.statemachine.StateContext;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Phase 2: MFA 초기화 액션 (MfaDecision 적용 포함)
 *
 * <p>
 * PolicyProvider로부터 받은 MfaDecision을 적용하여 Context를 초기화합니다.
 * Single Source of Truth 패턴 구현의 핵심 클래스.
 * </p>
 *
 * <p>
 * 실행 흐름:
 * 1. 기본 MFA 초기화 (타임스탬프, 클라이언트 정보)
 * 2. MfaDecision 적용 (메타데이터, availableFactors 등)
 * 3. 차단 결정 처리
 * 4. 에러 발생 시 SYSTEM_ERROR 상태로 전이
 * </p>
 *
 * @since Phase 2
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class InitializeMfaAction extends AbstractMfaStateAction {

    private final ApplicationContext applicationContext;

    @Override
    protected void doExecute(StateContext<MfaState, MfaEvent> context,
                             FactorContext factorContext) throws Exception {
        String sessionId = factorContext.getMfaSessionId();
        log.info("Initializing MFA for session: {}, user: {}",
                sessionId, factorContext.getUsername());

        // Step 1: 기본 초기화
        factorContext.setAttribute("mfaInitializedAt", System.currentTimeMillis());
        factorContext.setAttribute("primaryAuthCompleted", true);

        HttpServletRequest request = (HttpServletRequest) context.getMessageHeader("request");
        if (request != null) {
            factorContext.setAttribute("userAgent", request.getHeader("User-Agent"));
            factorContext.setAttribute("clientIp", request.getRemoteAddr());
        }

        // Step 2: Phase 2 - MfaDecision 적용
        MfaDecision decision = (MfaDecision) context.getMessageHeader("mfaDecision");
        if (decision != null) {
            applyMfaDecisionToContext(factorContext, decision);
        } else {
            log.warn("MfaDecision not found in message header for session: {}", sessionId);
        }

        log.info("MFA initialization completed for session: {}", sessionId);
    }

    /**
     * Phase 2: MfaDecision을 Context에 적용
     */
    private void applyMfaDecisionToContext(FactorContext ctx, MfaDecision decision) {
        String sessionId = ctx.getMfaSessionId();

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

                log.info("User {} can use {} DSL-defined MFA factors: {}",
                        ctx.getUsername(), availableFactors.size(), availableFactors);
            } else {
                // MFA FlowConfig 없으면 decision에서 가져오기
                List<AuthType> requiredFactors = decision.getRequiredFactors();
                if (requiredFactors != null && !requiredFactors.isEmpty()) {
                    Set<AuthType> availableFactors = new HashSet<>(requiredFactors);
                    ctx.setAttribute("availableFactors", availableFactors);
                    log.debug("Available factors loaded from decision for user: {}, factors: {}",
                            ctx.getUsername(), availableFactors);
                } else {
                    log.error("No available factors for user: {}. Configuration error.", ctx.getUsername());
                    ctx.changeState(MfaState.MFA_SYSTEM_ERROR);
                    ctx.setLastError("MFA configuration error: no available factors");
                }
            }
        }

        log.debug("MfaDecision applied to context for session: {}", sessionId);
    }

    /**
     * MFA FlowConfig 조회
     */
    private AuthenticationFlowConfig findMfaFlowConfig() {
        try {
            PlatformConfig platformConfig = applicationContext.getBean(PlatformConfig.class);
            if (platformConfig == null || platformConfig.getFlows() == null) {
                return null;
            }

            return platformConfig.getFlows().stream()
                .filter(f -> AuthType.MFA.name().equalsIgnoreCase(f.getTypeName()))
                .findFirst()
                .orElse(null);
        } catch (Exception e) {
            log.error("Error loading MFA flow config", e);
            return null;
        }
    }
}