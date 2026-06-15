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
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.mockito.quality.Strictness.*;
import static org.mockito.junit.jupiter.MockitoSettings.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@DisplayName("PasswordPolicyService")
class PasswordPolicyServiceTest {

    @Mock
    private PasswordPolicyRepository repository;

    @Mock
    private PasswordHistoryRepository passwordHistoryRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @InjectMocks
    private PasswordPolicyService service;

    @Nested
    @DisplayName("getCurrentPolicy")
    class GetCurrentPolicy {

        @Test
        @DisplayName("should return default policy when repository is empty")
        void emptyRepository() {
            when(repository.findAll()).thenReturn(Collections.emptyList());

            PasswordPolicy policy = service.getCurrentPolicy();

            assertThat(policy).isNotNull();
            assertThat(policy.getMinLength()).isEqualTo(8);
        }

        @Test
        @DisplayName("should return first policy when repository has elements")
        void hasElements() {
            PasswordPolicy mockPolicy = PasswordPolicy.builder()
                    .minLength(8)
                    .maxLength(20)
                    .build();
            when(repository.findAll()).thenReturn(List.of(mockPolicy));

            PasswordPolicy policy = service.getCurrentPolicy();

            assertThat(policy).isEqualTo(mockPolicy);
        }
    }

    @Nested
    @DisplayName("updatePolicy")
    class UpdatePolicy {

        @Test
        @DisplayName("should update and save existing policy properties")
        void success() {
            PasswordPolicy existing = PasswordPolicy.builder()
                    .minLength(6)
                    .build();
            when(repository.findAll()).thenReturn(List.of(existing));
            when(repository.save(any(PasswordPolicy.class))).thenAnswer(inv -> inv.getArgument(0));

            PasswordPolicy updateParam = PasswordPolicy.builder()
                    .minLength(10)
                    .maxLength(32)
                    .requireUppercase(true)
                    .requireLowercase(true)
                    .requireDigit(true)
                    .requireSpecialChar(true)
                    .maxFailedAttempts(5)
                    .lockoutDurationMinutes(15)
                    .ipMaxFailedAttempts(10)
                    .ipWindowMinutes(30)
                    .passwordExpiryDays(90)
                    .historyCount(3)
                    .build();

            PasswordPolicy result = service.updatePolicy(updateParam);

            assertThat(result.getMinLength()).isEqualTo(10);
            assertThat(result.getMaxLength()).isEqualTo(32);
            assertThat(result.isRequireUppercase()).isTrue();
            assertThat(result.isRequireLowercase()).isTrue();
            assertThat(result.isRequireDigit()).isTrue();
            assertThat(result.isRequireSpecialChar()).isTrue();
            assertThat(result.getMaxFailedAttempts()).isEqualTo(5);
            assertThat(result.getLockoutDurationMinutes()).isEqualTo(15);
            assertThat(result.getIpMaxFailedAttempts()).isEqualTo(10);
            assertThat(result.getIpWindowMinutes()).isEqualTo(30);
            assertThat(result.getPasswordExpiryDays()).isEqualTo(90);
            assertThat(result.getHistoryCount()).isEqualTo(3);
            verify(repository).save(existing);
        }
    }

    @Nested
    @DisplayName("validatePassword")
    class ValidatePassword {

        @Test
        @DisplayName("should return violation when password is null or empty")
        void nullOrEmpty() {
            when(repository.findAll()).thenReturn(Collections.emptyList());

            List<String> violationsNull = service.validatePassword(null);
            List<String> violationsEmpty = service.validatePassword("");

            assertThat(violationsNull).containsExactly("Password must not be empty");
            assertThat(violationsEmpty).containsExactly("Password must not be empty");
        }

        @Test
        @DisplayName("should validate minLength and maxLength")
        void lengthViolations() {
            PasswordPolicy policy = PasswordPolicy.builder()
                    .minLength(8)
                    .maxLength(12)
                    .requireUppercase(false)
                    .requireLowercase(false)
                    .requireDigit(false)
                    .build();
            when(repository.findAll()).thenReturn(List.of(policy));

            List<String> shortViolations = service.validatePassword("abc");
            List<String> longViolations = service.validatePassword("abcdefghijklmnop");

            assertThat(shortViolations).containsExactly("Password must be at least 8 characters");
            assertThat(longViolations).containsExactly("Password must not exceed 12 characters");
        }

        @Test
        @DisplayName("should validate uppercase and lowercase rules")
        void caseViolations() {
            PasswordPolicy policy = PasswordPolicy.builder()
                    .minLength(4)
                    .maxLength(20)
                    .requireUppercase(true)
                    .requireLowercase(true)
                    .requireDigit(false)
                    .build();
            when(repository.findAll()).thenReturn(List.of(policy));

            List<String> noUpper = service.validatePassword("abcd");
            List<String> noLower = service.validatePassword("ABCD");
            List<String> success = service.validatePassword("Abcd");

            assertThat(noUpper).containsExactly("Password must contain at least one uppercase letter");
            assertThat(noLower).containsExactly("Password must contain at least one lowercase letter");
            assertThat(success).isEmpty();
        }

        @Test
        @DisplayName("should validate digit and special character rules")
        void characterViolations() {
            PasswordPolicy policy = PasswordPolicy.builder()
                    .minLength(4)
                    .maxLength(20)
                    .requireDigit(true)
                    .requireSpecialChar(true)
                    .requireUppercase(false)
                    .requireLowercase(false)
                    .build();
            when(repository.findAll()).thenReturn(List.of(policy));

            List<String> noDigit = service.validatePassword("abc!");
            List<String> noSpecial = service.validatePassword("abc1");
            List<String> success = service.validatePassword("ab1!");

            assertThat(noDigit).containsExactly("Password must contain at least one digit");
            assertThat(noSpecial).containsExactly("Password must contain at least one special character");
            assertThat(success).isEmpty();
        }
    }

    @Nested
    @DisplayName("isPasswordReused")
    class IsPasswordReused {

        @Test
        @DisplayName("should return false when policy history count is zero or negative")
        void historyCountZero() {
            PasswordPolicy policy = PasswordPolicy.builder()
                    .historyCount(0)
                    .build();
            when(repository.findAll()).thenReturn(List.of(policy));

            boolean result = service.isPasswordReused(1L, "newPass");

            assertThat(result).isFalse();
            verifyNoInteractions(passwordHistoryRepository, passwordEncoder);
        }

        @Test
        @DisplayName("should return true when new password matches history within history count limit")
        void isReused() {
            PasswordPolicy policy = PasswordPolicy.builder()
                    .historyCount(2)
                    .build();
            when(repository.findAll()).thenReturn(List.of(policy));

            PasswordHistory h1 = PasswordHistory.builder().passwordHash("hash1").build();
            PasswordHistory h2 = PasswordHistory.builder().passwordHash("hash2").build();
            PasswordHistory h3 = PasswordHistory.builder().passwordHash("hash3").build();

            when(passwordHistoryRepository.findByUserIdOrderByChangedAtDesc(1L))
                    .thenReturn(List.of(h1, h2, h3));
            when(passwordEncoder.matches("myNewPassword", "hash1")).thenReturn(false);
            when(passwordEncoder.matches("myNewPassword", "hash2")).thenReturn(true);

            boolean result = service.isPasswordReused(1L, "myNewPassword");

            assertThat(result).isTrue();
            // verify we limit comparison to policy historyCount (2)
            verify(passwordEncoder).matches("myNewPassword", "hash1");
            verify(passwordEncoder).matches("myNewPassword", "hash2");
            verify(passwordEncoder, never()).matches("myNewPassword", "hash3");
        }

        @Test
        @DisplayName("should return false when new password does not match history within history count limit")
        void isNotReused() {
            PasswordPolicy policy = PasswordPolicy.builder()
                    .historyCount(2)
                    .build();
            when(repository.findAll()).thenReturn(List.of(policy));

            PasswordHistory h1 = PasswordHistory.builder().passwordHash("hash1").build();
            PasswordHistory h2 = PasswordHistory.builder().passwordHash("hash2").build();

            when(passwordHistoryRepository.findByUserIdOrderByChangedAtDesc(1L))
                    .thenReturn(List.of(h1, h2));
            when(passwordEncoder.matches("myNewPassword", "hash1")).thenReturn(false);
            when(passwordEncoder.matches("myNewPassword", "hash2")).thenReturn(false);

            boolean result = service.isPasswordReused(1L, "myNewPassword");

            assertThat(result).isFalse();
        }
    }

    @Nested
    @DisplayName("recordPasswordHistory")
    class RecordPasswordHistory {

        @Test
        @DisplayName("should save password history entry")
        void success() {
            service.recordPasswordHistory(1L, "myEncodedPassword");

            verify(passwordHistoryRepository).save(argThat(history ->
                    history.getUserId().equals(1L) &&
                    history.getPasswordHash().equals("myEncodedPassword")
            ));
        }
    }
}
