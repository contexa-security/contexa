package io.contexa.contexaidentity.security.statemachine.guard;

import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import lombok.extern.slf4j.Slf4j;
import org.springframework.statemachine.StateContext;
import org.springframework.stereotype.Component;

/**
 * 사용자 차단 상태 확인 Guard
 *
 * HandleFailureAction에서 설정한 blocked 속성을 확인하여
 * 차단된 사용자의 MFA 프로세스 진행을 방지합니다.
 *
 * Phase 2.3: blocked/blockReason 속성 활용
 */
@Slf4j
@Component
public class BlockedUserGuard extends AbstractMfaStateGuard {

    @Override
    protected boolean doEvaluate(StateContext<MfaState, MfaEvent> context,
                                 FactorContext factorContext) {
        String sessionId = factorContext.getMfaSessionId();
        String username = factorContext.getUsername();

        // blocked 속성 확인
        Object blockedObj = factorContext.getAttribute("blocked");
        boolean isBlocked = Boolean.TRUE.equals(blockedObj);

        if (isBlocked) {
            String blockReason = (String) factorContext.getAttribute("blockReason");
            log.warn("[BlockedUserGuard] User {} is blocked for session: {}, reason: {}",
                    username, sessionId, blockReason != null ? blockReason : "UNKNOWN");
            return false;
        }

        log.debug("[BlockedUserGuard] User {} is not blocked for session: {}",
                username, sessionId);
        return true;
    }

    @Override
    public String getFailureReason() {
        return "User is blocked from MFA process";
    }

    @Override
    public String getGuardName() {
        return "BlockedUserGuard";
    }

    /**
     * 사용자 차단 설정
     *
     * @param factorContext FactorContext
     * @param reason 차단 사유
     */
    public void blockUser(FactorContext factorContext, String reason) {
        factorContext.setAttribute("blocked", true);
        factorContext.setAttribute("blockReason", reason);
        factorContext.setAttribute("blockedAt", System.currentTimeMillis());

        log.warn("[BlockedUserGuard] User {} blocked for session: {}, reason: {}",
                factorContext.getUsername(), factorContext.getMfaSessionId(), reason);
    }

    /**
     * 사용자 차단 해제
     *
     * @param factorContext FactorContext
     */
    public void unblockUser(FactorContext factorContext) {
        factorContext.removeAttribute("blocked");
        factorContext.removeAttribute("blockReason");
        factorContext.removeAttribute("blockedAt");

        log.info("[BlockedUserGuard] User {} unblocked for session: {}",
                factorContext.getUsername(), factorContext.getMfaSessionId());
    }

    /**
     * 차단 여부 확인
     *
     * @param factorContext FactorContext
     * @return 차단 여부
     */
    public boolean isUserBlocked(FactorContext factorContext) {
        Object blockedObj = factorContext.getAttribute("blocked");
        return Boolean.TRUE.equals(blockedObj);
    }

    /**
     * 차단 사유 조회
     *
     * @param factorContext FactorContext
     * @return 차단 사유
     */
    public String getBlockReason(FactorContext factorContext) {
        return (String) factorContext.getAttribute("blockReason");
    }
}
