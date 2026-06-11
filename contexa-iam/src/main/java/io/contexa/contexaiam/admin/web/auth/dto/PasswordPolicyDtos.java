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
        private int ipMaxFailedAttempts = 30;
        private int ipWindowMinutes = 15;
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
            form.setIpMaxFailedAttempts(policy.getIpMaxFailedAttempts());
            form.setIpWindowMinutes(policy.getIpWindowMinutes());
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
                    .ipMaxFailedAttempts(ipMaxFailedAttempts)
                    .ipWindowMinutes(ipWindowMinutes)
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
