package io.contexa.contexaidentity.security.statemachine.action;

import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContextAttributes;
import io.contexa.contexaidentity.security.core.mfa.model.MfaDecision;
import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.statemachine.StateContext;
import org.springframework.stereotype.Component;

import java.io.Serializable;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

@Slf4j
public class InitializeMfaAction extends AbstractMfaStateAction {

    private final PlatformConfig platformConfig;

    public InitializeMfaAction(PlatformConfig platformConfig) {
        this.platformConfig = platformConfig;
    }

    @Override
    protected void doExecute(StateContext<MfaState, MfaEvent> context,
                             FactorContext factorContext) throws Exception {
        String sessionId = factorContext.getMfaSessionId();
        
        HttpServletRequest request = (HttpServletRequest) context.getMessageHeader("request");
        if (request != null) {
            factorContext.setAttribute(FactorContextAttributes.DeviceAndSession.USER_AGENT,
                                     request.getHeader("User-Agent"));
            factorContext.setAttribute(FactorContextAttributes.DeviceAndSession.CLIENT_IP,
                                     request.getRemoteAddr());
        }

        MfaDecision decision = (MfaDecision) context.getMessageHeader("mfaDecision");
        if (decision != null) {
            applyMfaDecisionToContext(factorContext, decision);
        } else {
            log.warn("MfaDecision not found in message header for session: {}", sessionId);
        }

            }

    private void applyMfaDecisionToContext(FactorContext ctx, MfaDecision decision) {
        String sessionId = ctx.getMfaSessionId();

        ctx.setMfaRequiredAsPerPolicy(decision.isRequired());
        
        ctx.setAttribute(FactorContextAttributes.StateControl.MFA_DECISION_TYPE,
                        decision.getType().name());

        if (decision.getMetadata() != null) {
            decision.getMetadata().forEach((key, value) -> {
                if (value == null || value instanceof Serializable) {
                    ctx.setAttribute(key, value);
                } else {
                    log.warn("Non-serializable metadata skipped for session {}: key={}, type={}",
                             sessionId, key, value.getClass().getName());
                }
            });
            
            if (decision.getMetadata().containsKey(FactorContextAttributes.StateControl.USER_INFO)) {
                            }
        }

        if (decision.isBlocked()) {
            ctx.setAttribute(FactorContextAttributes.StateControl.BLOCKED, true);
            ctx.setAttribute(FactorContextAttributes.MessageAndReason.BLOCK_REASON,
                           decision.getReason());
            log.warn("Authentication blocked for user {}: {}",
                    ctx.getUsername(), decision.getReason());
        }

        if (decision.isRequired()) {
            
            AuthenticationFlowConfig mfaFlowConfig = platformConfig.getFlows().stream()
                    .filter(flow -> AuthType.MFA.name().equalsIgnoreCase(flow.getTypeName()))
                    .findFirst()
                    .orElse(null);

            if (mfaFlowConfig != null) {
                
                Set<AuthType> availableFactors = new LinkedHashSet<>(mfaFlowConfig.getRegisteredFactorOptions().keySet());
                ctx.setAttribute(FactorContextAttributes.Policy.AVAILABLE_FACTORS, availableFactors);

                Set<AuthType> verifyFactors = ctx.getSetAttribute(FactorContextAttributes.Policy.AVAILABLE_FACTORS);
                if (verifyFactors == null || verifyFactors.isEmpty()) {
                    log.error("[InitializeMfaAction] availableFactors verification FAILED for session: {}",
                             ctx.getMfaSessionId());
                } else {
                                    }

                if (mfaFlowConfig.getStateConfig() != null) {
                    ctx.setStateConfig(mfaFlowConfig.getStateConfig());
                                    }

                            } else {
                
                List<AuthType> requiredFactors = decision.getRequiredFactors();
                if (requiredFactors != null && !requiredFactors.isEmpty()) {
                    Set<AuthType> availableFactors = new LinkedHashSet<>(requiredFactors);
                    ctx.setAttribute(FactorContextAttributes.Policy.AVAILABLE_FACTORS, availableFactors);
                                    } else {
                    log.error("No available factors for user: {}. Configuration error.", ctx.getUsername());
                    ctx.changeState(MfaState.MFA_SYSTEM_ERROR);
                    ctx.setLastError("MFA configuration error: no available factors");
                }
            }
        }

            }

}