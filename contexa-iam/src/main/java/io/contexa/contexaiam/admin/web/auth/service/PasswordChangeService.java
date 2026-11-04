package io.contexa.contexaiam.admin.web.auth.service;

import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacommon.security.LoginPolicyHandler;
import io.contexa.contexaiam.security.core.LoginPolicyService;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.cache.annotation.CacheConfig;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@RequiredArgsConstructor
@CacheConfig(cacheManager = "contexaCacheManager")
public class PasswordChangeService {

    private static final String POLICY_SOURCE = "PASSWORD_CHANGE";

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final PasswordPolicyService passwordPolicyService;
    private final ObjectProvider<LoginPolicyHandler> loginPolicy;

    /** Compared with when there is no password to compare with, so that an unknown name takes as long as a wrong password. */
    private volatile String decoyHash;

    /**
     * Reached before any sign-in, because an expired password cannot sign in, so the current password is all that stands
     * in front of the account. A wrong one counts as a failed sign-in (the lock, the address throttle), and whatever
     * refuses, an unknown name, a locked account or a blocked address, answers exactly as a wrong password does.
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
            return user;
        }
        // A locked account is not counted again: whoever keeps trying would keep extending the lock of its owner.
        if (policy != null && !locked) {
            policy.onLoginFailure(username, clientIp, "PasswordChange", POLICY_SOURCE);
        }
        throw new PasswordChangeException("msg.password.change.current.incorrect");
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