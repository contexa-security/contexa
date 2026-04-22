package io.contexa.contexaiam.admin.web.auth.dto;

import io.contexa.contexacommon.entity.PasswordPolicy;
import lombok.Data;

public final class PasswordPolicyDtos {

    private PasswordPolicyDtos() {
    }

    @Data
    public static class PasswordPolicyForm {
        private int minLength = 8;
        private int maxLength = 128;
        private boolean requireUppercase = true;
        private boolean requireLowercase = true;
        private boolean requireDigit = true;
        private boolean requireSpecialChar = false;
        private int maxFailedAttempts = 5;
        private int lockoutDurationMinutes = 30;
        private int passwordExpiryDays = 90;
        private int historyCount = 3;

        public static PasswordPolicyForm from(PasswordPolicy policy) {
            PasswordPolicyForm form = new PasswordPolicyForm();
            form.setMinLength(policy.getMinLength());
            form.setMaxLength(policy.getMaxLength());
            form.setRequireUppercase(policy.isRequireUppercase());
            form.setRequireLowercase(policy.isRequireLowercase());
            form.setRequireDigit(policy.isRequireDigit());
            form.setRequireSpecialChar(policy.isRequireSpecialChar());
            form.setMaxFailedAttempts(policy.getMaxFailedAttempts());
            form.setLockoutDurationMinutes(policy.getLockoutDurationMinutes());
            form.setPasswordExpiryDays(policy.getPasswordExpiryDays());
            form.setHistoryCount(policy.getHistoryCount());
            return form;
        }

        public PasswordPolicy toPasswordPolicy() {
            return PasswordPolicy.builder()
                    .minLength(minLength)
                    .maxLength(maxLength)
                    .requireUppercase(requireUppercase)
                    .requireLowercase(requireLowercase)
                    .requireDigit(requireDigit)
                    .requireSpecialChar(requireSpecialChar)
                    .maxFailedAttempts(maxFailedAttempts)
                    .lockoutDurationMinutes(lockoutDurationMinutes)
                    .passwordExpiryDays(passwordExpiryDays)
                    .historyCount(historyCount)
                    .build();
        }
    }

    public record PasswordPolicyRulesResponse(
            int minLength,
            int maxLength,
            boolean requireUppercase,
            boolean requireLowercase,
            boolean requireDigit,
            boolean requireSpecialChar
    ) {
        public static PasswordPolicyRulesResponse from(PasswordPolicy policy) {
            return new PasswordPolicyRulesResponse(
                    policy.getMinLength(),
                    policy.getMaxLength(),
                    policy.isRequireUppercase(),
                    policy.isRequireLowercase(),
                    policy.isRequireDigit(),
                    policy.isRequireSpecialChar()
            );
        }
    }
}
