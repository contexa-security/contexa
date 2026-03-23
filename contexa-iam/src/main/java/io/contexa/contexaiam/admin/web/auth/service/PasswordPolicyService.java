package io.contexa.contexaiam.admin.web.auth.service;

import io.contexa.contexacommon.entity.PasswordPolicy;
import io.contexa.contexacommon.repository.PasswordPolicyRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;

@RequiredArgsConstructor
public class PasswordPolicyService {

    private final PasswordPolicyRepository repository;

    @Transactional(readOnly = true)
    public PasswordPolicy getCurrentPolicy() {
        return repository.findAll().stream()
                .findFirst()
                .orElseGet(() -> repository.save(PasswordPolicy.builder().build()));
    }

    @Transactional
    public PasswordPolicy updatePolicy(PasswordPolicy policy) {
        PasswordPolicy existing = getCurrentPolicy();
        existing.setMinLength(policy.getMinLength());
        existing.setMaxLength(policy.getMaxLength());
        existing.setRequireUppercase(policy.isRequireUppercase());
        existing.setRequireLowercase(policy.isRequireLowercase());
        existing.setRequireDigit(policy.isRequireDigit());
        existing.setRequireSpecialChar(policy.isRequireSpecialChar());
        existing.setMaxFailedAttempts(policy.getMaxFailedAttempts());
        existing.setLockoutDurationMinutes(policy.getLockoutDurationMinutes());
        existing.setPasswordExpiryDays(policy.getPasswordExpiryDays());
        existing.setHistoryCount(policy.getHistoryCount());
        return repository.save(existing);
    }

    public List<String> validatePassword(String password) {
        PasswordPolicy policy = getCurrentPolicy();
        List<String> violations = new ArrayList<>();

        if (password == null || password.isEmpty()) {
            violations.add("Password must not be empty");
            return violations;
        }

        if (password.length() < policy.getMinLength()) {
            violations.add("Password must be at least " + policy.getMinLength() + " characters");
        }

        if (password.length() > policy.getMaxLength()) {
            violations.add("Password must not exceed " + policy.getMaxLength() + " characters");
        }

        if (policy.isRequireUppercase() && !password.matches(".*[A-Z].*")) {
            violations.add("Password must contain at least one uppercase letter");
        }

        if (policy.isRequireLowercase() && !password.matches(".*[a-z].*")) {
            violations.add("Password must contain at least one lowercase letter");
        }

        if (policy.isRequireDigit() && !password.matches(".*[0-9].*")) {
            violations.add("Password must contain at least one digit");
        }

        if (policy.isRequireSpecialChar() && !password.matches(".*[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>/?].*")) {
            violations.add("Password must contain at least one special character");
        }

        return violations;
    }
}
