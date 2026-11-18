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
import io.contexa.contexacommon.enums.AuditEventCategory;
import io.contexa.contexacommon.entity.PasswordPolicy;
import io.contexa.contexacommon.repository.PasswordHistoryRepository;
import io.contexa.contexacommon.repository.PasswordPolicyRepository;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import lombok.RequiredArgsConstructor;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.lang.Nullable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.ToIntFunction;

@RequiredArgsConstructor
@Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
public class PasswordPolicyService {

    private final PasswordPolicyRepository repository;
    private final PasswordHistoryRepository passwordHistoryRepository;
    private final PasswordEncoder passwordEncoder;
    /** The texts of the rules in the language of the request; without it they are English. */
    @Nullable
    private MessageSource messageSource;

    public void setMessageSource(@Nullable MessageSource messageSource) {
        this.messageSource = messageSource;
    }

    /** K75: a change of the policy is audited; without the facade nothing is recorded. */
    private AdminChangeAudit audit = AdminChangeAudit.NONE;
    /** K76: the accounts whose expired password a change of the policy's days changes; null changes none. */
    @Nullable
    private UserRepository accounts;

    /** K75: records the changes of the policy. */
    public void setCentralAuditFacade(CentralAuditFacade centralAuditFacade) {
        this.audit = AdminChangeAudit.of(centralAuditFacade);
    }

    /** K76: the accounts that say whether their password expired, set again when the policy is kept. */
    public void setAccounts(@Nullable UserRepository accounts) {
        this.accounts = accounts;
    }

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

    /**
     * K75: every value of the policy by its form field, and the label it is shown under; what a change of the policy is
     * recorded by (the dashboard names the values changed by their labels).
     */
    public static final Map<String, String> FIELD_LABELS = fieldLabels();

    private static Map<String, String> fieldLabels() {
        Map<String, String> labels = new LinkedHashMap<>();
        BOUNDS.forEach(bound -> labels.put(bound.field(), bound.labelKey()));
        labels.put("requireUppercase", "admin.password.policy.require.uppercase");
        labels.put("requireLowercase", "admin.password.policy.require.lowercase");
        labels.put("requireDigit", "admin.password.policy.require.digit");
        labels.put("requireSpecialChar", "admin.password.policy.require.special");
        return Collections.unmodifiableMap(labels);
    }

    private static Map<String, Object> values(PasswordPolicy policy) {
        Map<String, Object> values = new LinkedHashMap<>();
        BOUNDS.forEach(bound -> values.put(bound.field(), bound.value().applyAsInt(policy)));
        values.put("requireUppercase", policy.isRequireUppercase());
        values.put("requireLowercase", policy.isRequireLowercase());
        values.put("requireDigit", policy.isRequireDigit());
        values.put("requireSpecialChar", policy.isRequireSpecialChar());
        return values;
    }

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
        Map<String, Object> before = values(existing);
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
        PasswordPolicy saved = repository.save(existing);
        markExpiredPasswords(existing.getPasswordExpiryDays());
        auditChange(before, values(existing));
        return saved;
    }

    /**
     * K76: every account says whether its password is past the days the policy keeps now, as a sign-in reads it
     * (LoginPolicyService.isCredentialsExpired), so a policy that lets passwords live longer frees them at once.
     */
    private void markExpiredPasswords(int expiryDays) {
        if (accounts == null) {
            return;
        }
        if (expiryDays <= 0) {
            accounts.clearAllCredentialsExpired();
            return;
        }
        LocalDateTime changedBefore = LocalDateTime.now().minusDays(expiryDays);
        accounts.clearCredentialsExpiredChangedSince(changedBefore);
        accounts.markCredentialsExpiredChangedBefore(changedBefore);
    }

    /** K75: the values the change changed, before and after; a save that changed none records nothing. */
    private void auditChange(Map<String, Object> before, Map<String, Object> after) {
        Map<String, Object> was = new LinkedHashMap<>();
        Map<String, Object> now = new LinkedHashMap<>();
        after.forEach((field, value) -> {
            if (!Objects.equals(before.get(field), value)) {
                was.put(field, before.get(field));
                now.put(field, value);
            }
        });
        if (now.isEmpty()) {
            return;
        }
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("changed", List.copyOf(now.keySet()));
        details.put("before", was);
        details.put("after", now);
        audit.record(AuditEventCategory.PASSWORD_POLICY_CHANGED, AuditEventCategory.PASSWORD_POLICY_CHANGED.name(),
                String.join(",", now.keySet()), details);
    }

    public List<String> validatePassword(String password) {
        PasswordPolicy policy = getCurrentPolicy();
        List<String> violations = new ArrayList<>();

        if (password == null || password.isEmpty()) {
            violations.add(text("password.policy.not.empty", "Password must not be empty"));
            return violations;
        }

        if (password.length() < policy.getMinLength()) {
            violations.add(text("password.policy.min.length",
                    "Password must be at least " + policy.getMinLength() + " characters", policy.getMinLength()));
        }

        if (password.length() > policy.getMaxLength()) {
            violations.add(text("password.policy.max.length",
                    "Password must not exceed " + policy.getMaxLength() + " characters", policy.getMaxLength()));
        }

        if (policy.isRequireUppercase() && !password.matches(".*[A-Z].*")) {
            violations.add(text("password.policy.uppercase", "Password must contain at least one uppercase letter"));
        }

        if (policy.isRequireLowercase() && !password.matches(".*[a-z].*")) {
            violations.add(text("password.policy.lowercase", "Password must contain at least one lowercase letter"));
        }

        if (policy.isRequireDigit() && !password.matches(".*[0-9].*")) {
            violations.add(text("password.policy.digit", "Password must contain at least one digit"));
        }

        if (policy.isRequireSpecialChar() && !password.matches(".*[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>/?].*")) {
            violations.add(text("password.policy.special", "Password must contain at least one special character"));
        }

        return violations;
    }

    /** A rule's text in the language of the request; the English one without a message source. */
    private String text(String key, String english, Object... args) {
        return messageSource == null ? english
                : messageSource.getMessage(key, args, english, LocaleContextHolder.getLocale());
    }

    /**
     * Whether the new password is the one in use or one of the recent ones, when the policy keeps any (reuse prevention).
     * The one in use counts as the newest: changed to itself, a password would only start its expiry again.
     */
    public boolean isPasswordReused(Long userId, @Nullable String currentPasswordHash, String rawNewPassword) {
        if (getCurrentPolicy().getHistoryCount() <= 0) return false;
        if (currentPasswordHash != null && passwordEncoder.matches(rawNewPassword, currentPasswordHash)) return true;
        return isPasswordReused(userId, rawNewPassword);
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
