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
 * @since P1-1 ApplicationContext는 AbstractMfaStateAction으로부터 상속
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class InitializeMfaAction extends AbstractMfaStateAction {

    private final PlatformConfig platformConfig;

    @Override
    protected void doExecute(StateContext<MfaState, MfaEvent> context,
                             FactorContext factorContext) throws Exception {
        String sessionId = factorContext.getMfaSessionId();
        log.info("Initializing MFA for session: {}, user: {}",
                sessionId, factorContext.getUsername());

        HttpServletRequest request = (HttpServletRequest) context.getMessageHeader("request");
        if (request != null) {
            factorContext.setAttribute("userAgent", request.getHeader("User-Agent"));
            factorContext.setAttribute("clientIp", request.getRemoteAddr());
        }

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
        // Phase 3.4: MfaDecision 객체는 Kryo 직렬화 불가(no-arg 생성자 없음)이므로 필요한 정보만 저장
        ctx.setAttribute("mfaDecisionType", decision.getType().name());
        ctx.setAttribute("requiredFactorCount", decision.getFactorCount());
        ctx.setAttribute("mfaDecisionReason", decision.getReason());

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
            // Phase 2 개선: ApplicationContext bean lookup 제거 → 직접 주입된 PlatformConfig 사용
            AuthenticationFlowConfig mfaFlowConfig = platformConfig.getFlows().stream()
                    .filter(flow -> AuthType.MFA.name().equalsIgnoreCase(flow.getTypeName()))
                    .findFirst()
                    .orElse(null);

            if (mfaFlowConfig != null) {
                // Phase 3.4: Defensive copy for serialization safety
                Set<AuthType> availableFactors = new HashSet<>(mfaFlowConfig.getRegisteredFactorOptions().keySet());
                ctx.setAttribute("availableFactors", availableFactors);

                // Phase 3.4: Store only serializable values instead of entire config
                ctx.setAttribute("flowTypeName", mfaFlowConfig.getTypeName());
                ctx.setAttribute("flowOrder", mfaFlowConfig.getOrder());

                log.info("[InitializeMfaAction] Set availableFactors: {} (count: {}) for session: {}, version: {}",
                         availableFactors, availableFactors.size(), ctx.getMfaSessionId(), ctx.getVersion());

                // 즉시 ExtendedState에 반영 확인 (Phase 3.3: Type-safe getter 사용)
                Set<AuthType> verifyFactors = ctx.getSetAttribute("availableFactors");
                if (verifyFactors == null || verifyFactors.isEmpty()) {
                    log.error("[InitializeMfaAction] availableFactors verification FAILED for session: {}",
                             ctx.getMfaSessionId());
                } else {
                    log.debug("[InitializeMfaAction] availableFactors verified: {} for session: {}",
                             verifyFactors, ctx.getMfaSessionId());
                }

                // StateConfig 설정 (OAuth2/Session 구분을 위해)
                if (mfaFlowConfig.getStateConfig() != null) {
                    ctx.setStateConfig(mfaFlowConfig.getStateConfig());
                    log.debug("StateConfig set for session {}: {}",
                            sessionId, mfaFlowConfig.getStateConfig().stateType());
                }

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

    // Phase 2 개선: findMfaFlowConfig() 호출 제거 - ApplicationContext blocking 제거
}