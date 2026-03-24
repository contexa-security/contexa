package io.contexa.contexaiam.security.core;

import io.contexa.contexacommon.entity.PasswordPolicy;
import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacommon.security.LoginPolicyHandler;
import io.contexa.contexaiam.admin.web.auth.service.PasswordPolicyService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Slf4j
@RequiredArgsConstructor
public class LoginPolicyService implements LoginPolicyHandler {

    private final UserRepository userRepository;
    private final PasswordPolicyService passwordPolicyService;

    @Override
    @Transactional
    public void onLoginSuccess(String username, String ip) {
        userRepository.findByUsername(username).ifPresent(user -> {
            user.setFailedLoginAttempts(0);
            user.setLastLoginAt(LocalDateTime.now());
            user.setLastLoginIp(ip);
            userRepository.save(user);
        });
    }

    @Override
    @Transactional
    public void onLoginFailure(String username) {
        userRepository.findByUsername(username).ifPresent(user -> {
            int attempts = user.getFailedLoginAttempts() + 1;
            user.setFailedLoginAttempts(attempts);

            PasswordPolicy policy = passwordPolicyService.getCurrentPolicy();
            if (policy.getMaxFailedAttempts() > 0 && attempts >= policy.getMaxFailedAttempts()) {
                user.setAccountLocked(true);
                user.setLockExpiresAt(LocalDateTime.now().plusMinutes(policy.getLockoutDurationMinutes()));
                log.error("Account locked due to {} failed attempts: {}", attempts, username);
            }

            userRepository.save(user);
        });
    }

    @Override
    @Transactional
    public boolean checkAndUnlockIfExpired(String username) {
        return userRepository.findByUsername(username).map(user -> {
            if (user.isAccountLocked() && user.getLockExpiresAt() != null
                    && LocalDateTime.now().isAfter(user.getLockExpiresAt())) {
                user.setAccountLocked(false);
                user.setFailedLoginAttempts(0);
                user.setLockExpiresAt(null);
                userRepository.save(user);
                return true;
            }
            return false;
        }).orElse(false);
    }

    @Override
    @Transactional(readOnly = true)
    public boolean isCredentialsExpired(String username) {
        PasswordPolicy policy = passwordPolicyService.getCurrentPolicy();
        if (policy.getPasswordExpiryDays() <= 0) {
            return false;
        }

        return userRepository.findByUsername(username).map(user -> {
            LocalDateTime changedAt = user.getPasswordChangedAt();
            if (changedAt == null) {
                return false;
            }
            return LocalDateTime.now().isAfter(changedAt.plusDays(policy.getPasswordExpiryDays()));
        }).orElse(false);
    }
}
