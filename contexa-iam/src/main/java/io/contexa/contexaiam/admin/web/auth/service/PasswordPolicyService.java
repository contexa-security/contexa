/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexaiam.admin.web.auth.service;

import io.contexa.contexacommon.entity.PasswordHistory;
import io.contexa.contexacommon.entity.PasswordPolicy;
import io.contexa.contexacommon.repository.PasswordHistoryRepository;
import io.contexa.contexacommon.repository.PasswordPolicyRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.ToIntFunction;

@RequiredArgsConstructor
@Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
public class PasswordPolicyService {

    private final PasswordPolicyRepository repository;
    private final PasswordHistoryRepository passwordHistoryRepository;
    private final PasswordEncoder passwordEncoder;

    /**
     * The values a policy may take, as the console's form offers them: outside them a policy is one no password can meet
     * (a maximum length below the minimum), or one that holds no one (no failed attempt allowed, a lock of no minutes).
     */
    public static final List<Bound> BOUNDS = List.of(
            new Bound("minLength", "admin.password.policy.min.length", 1, 128, PasswordPolicy::getMinLength),
            new Bound("maxLength", "admin.password.policy.max.length", 1, 512, PasswordPolicy::getMaxLength),
            new Bound("maxFailedAttempts", "admin.password.policy.max.failed", 1, 100, PasswordPolicy::getMaxFailedAttempts),
            new Bound("lockoutDurationMinutes", "admin.password.policy.lockout.duration", 1, 10080,
                    PasswordPolicy::getLockoutDurationMinutes),
            new Bound("ipMaxFailedAttempts", "admin.password.policy.ip.max.failed", 0, 10000,
                    PasswordPolicy::getIpMaxFailedAttempts),
            new Bound("ipWindowMinutes", "admin.password.policy.ip.window", 1, 1440, PasswordPolicy::getIpWindowMinutes),
            new Bound("passwordExpiryDays", "admin.password.policy.expiry.days", 0, 365, PasswordPolicy::getPasswordExpiryDays),
            new Bound("historyCount", "admin.password.policy.history.count", 0, 24, PasswordPolicy::getHistoryCount));

    /** The value of a policy named by its form field, the label it is shown under, and the values it may take. */
    public record Bound(String field, String labelKey, int min, int max, ToIntFunction<PasswordPolicy> value) {

        public static Optional<Bound> of(String field) {
            return BOUNDS.stream().filter(bound -> bound.field().equals(field)).findFirst();
        }
    }

    /**
     * A policy the console refuses to keep, with the message that says why: the key, and the label key of the value
     * that is refused (null when the refusal names none) followed by the other arguments.
     */
    public static final class PolicyRefusedException extends IllegalArgumentException {

        private final String messageKey;
        private final String labelKey;
        private final Object[] messageArgs;

        public PolicyRefusedException(String messageKey, String labelKey, Object... messageArgs) {
            super("Password policy refused: " + messageKey + (labelKey != null ? " " + labelKey : ""));
            this.messageKey = messageKey;
            this.labelKey = labelKey;
            this.messageArgs = messageArgs;
        }

        public String getMessageKey() {
            return messageKey;
        }

        public String getLabelKey() {
            return labelKey;
        }

        public Object[] getMessageArgs() {
            return messageArgs.clone();
        }
    }

    public PasswordPolicy getCurrentPolicy() {
        return repository.findAll().stream()
                .findFirst()
                .orElseGet(() -> PasswordPolicy.builder().build());
    }

    /**
     * Keeps the policy, refused when a value is outside what it may take or the maximum length is below the minimum:
     * every password change, user registration and administrator's password setting is checked against it.
     *
     * @throws PolicyRefusedException when the policy is not kept
     */
    @Transactional(transactionManager = "contexaTransactionManager")
    public PasswordPolicy updatePolicy(PasswordPolicy policy) {
        for (Bound bound : BOUNDS) {
            int value = bound.value().applyAsInt(policy);
            if (value < bound.min() || value > bound.max()) {
                throw new PolicyRefusedException("admin.password.policy.refused.range", bound.labelKey(),
                        bound.min(), bound.max());
            }
        }
        if (policy.getMaxLength() < policy.getMinLength()) {
            throw new PolicyRefusedException("common.validation.min.length.exceeds.max", null);
        }
        PasswordPolicy existing = getCurrentPolicy();
        existing.setMinLength(policy.getMinLength());
        existing.setMaxLength(policy.getMaxLength());
        existing.setRequireUppercase(policy.isRequireUppercase());
        existing.setRequireLowercase(policy.isRequireLowercase());
        existing.setRequireDigit(policy.isRequireDigit());
        existing.setRequireSpecialChar(policy.isRequireSpecialChar());
        existing.setMaxFailedAttempts(policy.getMaxFailedAttempts());
        existing.setLockoutDurationMinutes(policy.getLockoutDurationMinutes());
        existing.setIpMaxFailedAttempts(policy.getIpMaxFailedAttempts());
        existing.setIpWindowMinutes(policy.getIpWindowMinutes());
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

    /**
     * Checks if the new password was recently used (reuse prevention).
     * Returns true if the password is reused and should be rejected.
     */
    public boolean isPasswordReused(Long userId, String rawNewPassword) {
        PasswordPolicy policy = getCurrentPolicy();
        if (policy.getHistoryCount() <= 0) return false;

        List<PasswordHistory> history = passwordHistoryRepository
                .findByUserIdOrderByChangedAtDesc(userId);

        return history.stream()
                .limit(policy.getHistoryCount())
                .anyMatch(h -> passwordEncoder.matches(rawNewPassword, h.getPasswordHash()));
    }

    /**
     * Records the current password in history before changing it.
     */
    @Transactional(transactionManager = "contexaTransactionManager")
    public void recordPasswordHistory(Long userId, String encodedPassword) {
        passwordHistoryRepository.save(PasswordHistory.builder()
                .userId(userId)
                .passwordHash(encodedPassword)
                .build());
    }
}
