package io.contexa.contexaidentity.security.core.mfa;/*
package io.contexa.contexaidentity.security.core.mfa;

import io.contexa.contexaidentity.security.core.mfa.context.ContextPersistence;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
@Component
@RequiredArgsConstructor
public class SecureContextPersistence implements ContextPersistence {

    private static final String CONTEXT_ATTR = "MFA_FACTOR_CONTEXT";
    private static final String CHALLENGE_NONCE_ATTR = "MFA_CHALLENGE_NONCE";

    private final CsrfTokenRepository csrfTokenRepository;
    private final SecureRandom secureRandom = new SecureRandom();

    // 챌린지 nonce 관리 (재생 공격 방지)
    private final ConcurrentHashMap<String, ChallengeNonce> challengeNonces = new ConcurrentHashMap<>();

    @Override
    public void saveContext(FactorContext context, HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            log.warn("No session available to save FactorContext");
            return;
        }

        // 1차 인증 후 세션 ID 변경 (세션 고정 공격 방지)
        if (shouldChangeSessionId(context)) {
            request.changeSessionId();
            log.info("Session ID changed for user: {}", context.getUsername());
        }

        // Context 저장
        session.setAttribute(CONTEXT_ATTR, context);

        // CSRF 토큰 갱신
        CsrfToken csrfToken = csrfTokenRepository.generateToken(request);
        csrfTokenRepository.saveToken(csrfToken, request, null);

        log.debug("FactorContext saved for session: {}", context.getMfaSessionId());
    }

    @Override
    public FactorContext contextLoad(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return null;
        }

        FactorContext context = (FactorContext) session.getAttribute(CONTEXT_ATTR);

        if (context != null) {
            // 세션 타임아웃 검증
            if (isSessionExpired(context)) {
                log.warn("MFA session expired for user: {}", context.getUsername());
                deleteContext(request);
                return null;
            }

            // 활동 시간 업데이트
            context.updateLastActivityTimestamp();
        }

        return context;
    }

    @Override
    public void deleteContext(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.removeAttribute(CONTEXT_ATTR);
            session.removeAttribute(CHALLENGE_NONCE_ATTR);
        }
    }

    */
/**
     * 챌린지 nonce 생성 및 저장 (재생 공격 방지)
     *//*

    public String generateChallengeNonce(String sessionId, String factorType) {
        byte[] nonceBytes = new byte[32];
        secureRandom.nextBytes(nonceBytes);
        String nonce = Base64.getUrlEncoder().withoutPadding().encodeToString(nonceBytes);

        ChallengeNonce challengeNonce = new ChallengeNonce(nonce, factorType, System.currentTimeMillis());
        challengeNonces.put(sessionId + ":" + factorType, challengeNonce);

        return nonce;
    }

    */
/**
     * 챌린지 nonce 검증 및 제거 (일회성 보장)
     *//*

    public boolean validateAndConsumeChallengeNonce(String sessionId, String factorType, String nonce) {
        String key = sessionId + ":" + factorType;
        ChallengeNonce storedNonce = challengeNonces.remove(key);

        if (storedNonce == null) {
            log.warn("No challenge nonce found for session: {}, factor: {}", sessionId, factorType);
            return false;
        }

        // nonce 만료 검증 (5분)
        if (System.currentTimeMillis() - storedNonce.createdAt > 300000) {
            log.warn("Challenge nonce expired for session: {}", sessionId);
            return false;
        }

        // nonce 일치 검증
        boolean valid = storedNonce.nonce.equals(nonce);
        if (!valid) {
            log.warn("Invalid challenge nonce for session: {}", sessionId);
        }

        return valid;
    }

    private boolean shouldChangeSessionId(FactorContext context) {
        // PRIMARY_AUTHENTICATION_COMPLETED 상태일 때 세션 ID 변경
        return context.getCurrentState() == MfaState.PRIMARY_AUTHENTICATION_COMPLETED;
    }

    private boolean isSessionExpired(FactorContext context) {
        // 30분 타임아웃
        long sessionTimeout = 30 * 60 * 1000;
        return System.currentTimeMillis() - context.getCreatedAt() > sessionTimeout;
    }

    // 챌린지 nonce 정보
    private static class ChallengeNonce {
        final String nonce;
        final String factorType;
        final long createdAt;

        ChallengeNonce(String nonce, String factorType, long createdAt) {
            this.nonce = nonce;
            this.factorType = factorType;
            this.createdAt = createdAt;
        }
    }
}
*/
