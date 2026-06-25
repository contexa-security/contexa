package io.contexa.contexaiam.admin.web.auth.service;

import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.repository.UserRepository;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

@RequiredArgsConstructor
public class PasswordChangeService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final PasswordPolicyService passwordPolicyService;

    @Transactional(transactionManager = "contexaTransactionManager")
    @CacheEvict(value = "usersWithAuthorities", allEntries = true)
    public void changePassword(String username, String currentPassword, String newPassword, String confirmPassword) {
        Users user = userRepository.findByUsername(username)
                .orElseThrow(() -> new PasswordChangeException("msg.password.change.user.not.found"));

        if (!passwordEncoder.matches(currentPassword, user.getPassword())) {
            throw new PasswordChangeException("msg.password.change.current.incorrect");
        }
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