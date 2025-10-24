package io.contexa.contexaidentity.security.statemachine.guard;

import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import io.contexa.contexaidentity.security.statemachine.support.StateContextHelper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.statemachine.StateContext;
import org.springframework.statemachine.guard.Guard;

/**
 * MFA State Guard의 추상 기본 클래스
 */
@Slf4j
public abstract class AbstractMfaStateGuard implements Guard<MfaState, MfaEvent>, MfaStateGuard {


    @Override
    public final boolean evaluate(StateContext<MfaState, MfaEvent> context) {
        try {
            // FactorContext 추출
            FactorContext factorContext = extractFactorContext(context);
            if (factorContext == null) {
                log.warn("FactorContext not found in state context for guard: {}", getGuardName());
                return false;
            }

            // Guard 로직 실행
            boolean result = doEvaluate(context, factorContext);

            log.debug("Guard {} evaluated to: {} for session: {}",
                    getGuardName(), result, factorContext.getMfaSessionId());

            return result;

        } catch (Exception e) {
            log.error("Error evaluating guard: {}", getGuardName(), e);
            return false;
        }
    }

    /**
     * 실제 Guard 로직 구현
     */
    protected abstract boolean doEvaluate(StateContext<MfaState, MfaEvent> context,
                                          FactorContext factorContext);

    /**
     * StateContext에서 FactorContext 추출
     */
    protected FactorContext extractFactorContext(StateContext<MfaState, MfaEvent> context) {
        return StateContextHelper.getFactorContext(context);
    }

    /**
     * Guard의 논리적 부정 반환
     */
    public Guard<MfaState, MfaEvent> negate() {
        return context -> !this.evaluate(context);
    }

    @Override
    public abstract String getFailureReason();

    @Override
    public abstract String getGuardName();
}