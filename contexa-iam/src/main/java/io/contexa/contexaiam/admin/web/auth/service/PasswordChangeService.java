package io.contexa.contexaiam.admin.web.auth.service;

import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacommon.security.LoginPolicyHandler;
import io.contexa.contexacommon.security.MfaPendingSession;
import io.contexa.contexacommon.security.UserPasswordChangedEvent;
import io.contexa.contexacommon.security.bridge.BridgeRequestAttributes;
import io.contexa.contexacommon.security.bridge.stamp.DelegationStamp;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustSubject;
import io.contexa.contexacore.autonomous.utils.SessionFingerprintUtil;
import io.contexa.contexaiam.security.core.LoginPolicyService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.cache.annotation.CacheConfig;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.LocalDateTime;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.function.BooleanSupplier;

@Slf4j
@RequiredArgsConstructor
@CacheConfig(cacheManager = "contexaCacheManager")
public class PasswordChangeService {

    private static final String POLICY_SOURCE = "PASSWORD_CHANGE";
    private static final String CURRENT_PASSWORD_REFUSED = "msg.password.change.current.incorrect";
    private static final AuthenticationTrustResolver TRUST_RESOLVER = new AuthenticationTrustResolverImpl();
    /** A session answers its restriction first: the password it knows is what the restriction doubts. */
    private static final Set<ZeroTrustAction> STOPS_A_SESSION =
            EnumSet.of(ZeroTrustAction.CHALLENGE, ZeroTrustAction.BLOCK, ZeroTrustAction.ESCALATE);
    /** An account that cannot sign in cannot answer a CHALLENGE either, which leaves it to what refuses the user. */
    private static final Set<ZeroTrustAction> STOPS_AN_EXPIRED_ACCOUNT =
            EnumSet.of(ZeroTrustAction.BLOCK, ZeroTrustAction.ESCALATE);

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final PasswordPolicyService passwordPolicyService;
    private final ObjectProvider<LoginPolicyHandler> loginPolicy;
    private final ObjectProvider<ZeroTrustActionRepository> decisions;
    private final BooleanSupplier decisionsEnforced;
    private final ApplicationEventPublisher eventPublisher;

    /** Compared with when there is no password to compare with, so that an unknown name takes as long as a wrong password. */
    private volatile String decoyHash;

    /**
     * Serves two people. An account whose password expired cannot sign in, so it reaches this before any sign-in, with the
     * current password as all that stands in front of it; the owner who is signed in comes from the console. Anybody else
     * who holds the password belongs at the sign-in and its second factor: a change here would pass that factor by and
     * lock the owner out.
     * <p>
     * A wrong password counts as a failed sign-in (the lock, the address throttle), unless the address is blocked, and
     * whatever refuses, an unknown name, a locked account, a blocked address or the right password of someone who may not
     * change it here, answers exactly as a wrong password does.
     * <p>
     * {@code noRollbackFor}: the failure is counted in this transaction and has to outlive the exception that reports it.
     */
    @Transactional(transactionManager = "contexaTransactionManager", noRollbackFor = PasswordChangeException.class)
    @CacheEvict(value = "usersWithAuthorities", allEntries = true)
    public void changePassword(String username, String currentPassword, String newPassword, String confirmPassword,
                               String clientIp) {
        try {
            change(verifiedAccount(username, currentPassword, clientIp), newPassword, confirmPassword);
        } finally {
            // Cleared at the end of each request by a filter that is registered only when Contexa owns sign-in.
            LoginPolicyService.clearRequestState();
        }
    }

    private Users verifiedAccount(String username, String currentPassword, String clientIp) {
        LoginPolicyHandler policy = loginPolicy.getIfAvailable();
        boolean addressBlocked = false;
        if (policy != null) {
            addressBlocked = policy.isIpBlocked(clientIp);
            policy.checkAndUnlockIfExpired(username);
        }
        Users user = userRepository.findByUsername(username).orElse(null);
        boolean hasPassword = user != null && user.getPassword() != null;
        boolean matches = passwordEncoder.matches(currentPassword, hasPassword ? user.getPassword() : decoyHash());
        boolean locked = user != null && user.isAccountLocked();
        if (hasPassword && matches && !locked && !addressBlocked) {
            if (mayChange(user, policy)) {
                return user;
            }
            // Not counted: the password is right, and counting it would let whoever holds it lock its owner out.
            log.warn("[PasswordChange] The right current password was refused: username={}", user.getUsername());
            throw new PasswordChangeException(CURRENT_PASSWORD_REFUSED);
        }
        // A locked account is not counted again: whoever keeps trying would keep extending the lock of its owner. A blocked
        // address is refused unheard, as at a sign-in: its attempt says nothing of the account, and counting it would hand
        // the address the lock of anyone's account.
        if (policy != null && !locked && !addressBlocked) {
            policy.onLoginFailure(username, clientIp, "PasswordChange", POLICY_SOURCE);
        }
        throw new PasswordChangeException(CURRENT_PASSWORD_REFUSED);
    }

    /** Whether whoever proved the current password may change it. Read after the proof: nothing here answers a guess. */
    private boolean mayChange(Users user, @Nullable LoginPolicyHandler policy) {
        if (!user.isEnabled() || user.isExternalAuthOnly()) {
            return false;
        }
        Authentication signedIn = signedIn();
        if (signedIn != null && !user.getUsername().equals(signedIn.getName())) {
            return false;
        }
        HttpServletRequest request = currentRequest();
        if (signedIn != null && !MfaPendingSession.of(request) && !agentActing(request)) {
            // The session's own context: of the sessions under a CHALLENGE, the one that answered it goes on.
            return !stoppedBy(STOPS_A_SESSION, user, SessionFingerprintUtil.generateContextBindingHash(request));
        }
        return expired(user, policy) && !stoppedBy(STOPS_AN_EXPIRED_ACCOUNT, user, null);
    }

    @Nullable
    private static Authentication signedIn() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return authentication != null && authentication.isAuthenticated() && !TRUST_RESOLVER.isAnonymous(authentication)
                ? authentication : null;
    }

    @Nullable
    private static HttpServletRequest currentRequest() {
        return RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attributes
                ? attributes.getRequest() : null;
    }

    /** A delegated token names the person, and the agent that carries it has not signed in as anybody. */
    private static boolean agentActing(@Nullable HttpServletRequest request) {
        return request != null
                && request.getAttribute(BridgeRequestAttributes.DELEGATION_STAMP) instanceof DelegationStamp stamp
                && StringUtils.hasText(stamp.agentId());
    }

    private static boolean expired(Users user, @Nullable LoginPolicyHandler policy) {
        return user.isCredentialsExpired() || (policy != null && policy.isCredentialsExpired(user.getUsername()));
    }

    /**
     * Whether a decision in force stops the change. A decision stops it under enforcement only, as everywhere else. The
     * built-in repositories answer from what they last read while their store is down, so a read that fails is a store of
     * the application's own: nothing is known of the user then, and the change waits.
     *
     * @param contextBinding the context to read for, null for the user's decision whatever request asks
     */
    private boolean stoppedBy(Set<ZeroTrustAction> stopping, Users user, @Nullable String contextBinding) {
        ZeroTrustActionRepository repository = decisions.getIfAvailable();
        if (repository == null || !decisionsEnforced.getAsBoolean()) {
            return false;
        }
        try {
            return stopping.contains(repository.currentActionOf(ZeroTrustSubject.of(user.getUsername(), null), contextBinding));
        } catch (RuntimeException e) {
            log.error("[PasswordChange] The decision of an account could not be read; its password stays: username={}",
                    user.getUsername(), e);
            return true;
        }
    }

    private String decoyHash() {
        String hash = decoyHash;
        if (hash == null) {
            hash = passwordEncoder.encode(UUID.randomUUID().toString());
            decoyHash = hash;
        }
        return hash;
    }

    private void change(Users user, String newPassword, String confirmPassword) {
        if (newPassword == null || !newPassword.equals(confirmPassword)) {
            throw new PasswordChangeException("msg.password.change.mismatch");
        }

        List<String> violations = passwordPolicyService.validatePassword(newPassword);
        if (!violations.isEmpty()) {
            throw new PasswordChangeException("msg.password.change.policy.violation", String.join(", ", violations));
        }
        if (passwordPolicyService.isPasswordReused(user.getId(), newPassword)) {
            throw new PasswordChangeException("msg.password.change.reused");
        }

        passwordPolicyService.recordPasswordHistory(user.getId(), user.getPassword());
        user.setPassword(passwordEncoder.encode(newPassword));
        user.setPasswordChangedAt(LocalDateTime.now());
        user.setCredentialsExpired(false);
        userRepository.save(user);
        // The listeners run after the commit: a change that rolls back ends nothing.
        eventPublisher.publishEvent(new UserPasswordChangedEvent(user.getUsername()));
    }

    @Getter
    public static class PasswordChangeException extends RuntimeException {
        private final String messageKey;
        private final Object[] messageArgs;

        public PasswordChangeException(String messageKey, Object... messageArgs) {
            super(messageKey);
            this.messageKey = messageKey;
            this.messageArgs = messageArgs == null ? new Object[0] : messageArgs;
        }
    }
}