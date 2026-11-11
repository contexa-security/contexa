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

import io.contexa.contexacommon.entity.SystemSettings;
import io.contexa.contexacommon.repository.RoleRepository;
import io.contexa.contexacommon.repository.SystemSettingsRepository;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexaiam.admin.web.auth.dto.SystemSettingsDtos.SystemSettingsForm;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("SystemSettingsService")
class SystemSettingsServiceTest {

    @Mock
    private SystemSettingsRepository repository;

    @Mock
    private RoleRepository roleRepository;

    @InjectMocks
    private SystemSettingsService service;

    @Nested
    @DisplayName("getSettings")
    class GetSettings {

        @Test
        @DisplayName("should return default settings when repository is empty")
        void emptyRepository() {
            when(repository.findAll()).thenReturn(Collections.emptyList());

            SystemSettings settings = service.getSettings();

            assertThat(settings).isNotNull();
            assertThat(settings.getDefaultRole()).isEqualTo("ROLE_USER");
            assertThat(settings.getMvcResourceScannerBasePackages()).isEqualTo("io.contexa.contexaiam.");
        }

        @Test
        @DisplayName("should return first settings when repository has elements")
        void hasElements() {
            SystemSettings mockSettings = SystemSettings.builder()
                    .defaultRole("ROLE_USER")
                    .build();
            when(repository.findAll()).thenReturn(List.of(mockSettings));

            SystemSettings settings = service.getSettings();

            assertThat(settings).isEqualTo(mockSettings);
        }
    }

    @Nested
    @DisplayName("updateSettings")
    class UpdateSettings {

        @Test
        @DisplayName("should create new settings and save when repository is empty")
        void emptyRepository() {
            when(repository.findAll()).thenReturn(Collections.emptyList());
            SystemSettings newSettings = new SystemSettings();
            when(repository.save(any(SystemSettings.class))).thenReturn(newSettings);

            SystemSettingsForm form = validForm();
            form.setAuditLogRetentionDays(30);
            form.setDefaultRole("ROLE_MEMBER");
            form.setPolicyCombiningAlgorithm("DENY_OVERRIDES");
            form.setRegistrationEnabled(true);

            service.updateSettings(form);

            verify(repository, times(1)).save(argThat(settings ->
                    settings.getAuditLogRetentionDays() == 90 &&
                    "ROLE_USER".equals(settings.getDefaultRole())
            ));
            verify(repository, times(2)).save(any(SystemSettings.class));
            assertThat(newSettings.getAuditLogRetentionDays()).isEqualTo(30);
            assertThat(newSettings.getDefaultRole()).isEqualTo("ROLE_MEMBER");
            assertThat(newSettings.getPolicyCombiningAlgorithm()).isEqualTo("DENY_OVERRIDES");
            assertThat(newSettings.isRegistrationEnabled()).isTrue();
            assertThat(newSettings.getMvcResourceScannerBasePackages()).isEqualTo("io.contexa.contexaiam.\nio.contexa.contexaiamenterprise.");
        }

        @Test
        @DisplayName("should update existing settings when repository has elements")
        void hasElements() {
            SystemSettings existing = SystemSettings.builder()
                    .auditLogRetentionDays(10)
                    .defaultRole("ROLE_USER")
                    .build();
            when(repository.findAll()).thenReturn(List.of(existing));

            SystemSettingsForm form = validForm();
            form.setAuditLogRetentionDays(90);
            form.setDefaultRole("ROLE_ADMIN");
            form.setPolicyCombiningAlgorithm("PERMIT_OVERRIDES");
            form.setRegistrationEnabled(false);

            service.updateSettings(form);

            verify(repository).save(existing);
            assertThat(existing.getAuditLogRetentionDays()).isEqualTo(90);
            assertThat(existing.getDefaultRole()).isEqualTo("ROLE_ADMIN");
            assertThat(existing.getPolicyCombiningAlgorithm()).isEqualTo("PERMIT_OVERRIDES");
            assertThat(existing.isRegistrationEnabled()).isFalse();
            assertThat(existing.getNoMatchingUrlPolicyDecision()).as("the form's default").isEqualTo("AUTHENTICATED");
            assertThat(existing.getMissingMethodPolicyDecision()).isEqualTo("PERMIT");
        }

        @Test
        @DisplayName("should store AUTHENTICATED for URLs and refuse it for methods")
        void authenticatedIsADecisionForUrlsOnly() {
            SystemSettings existing = SystemSettings.builder().noMatchingUrlPolicyDecision("PERMIT").build();
            when(repository.findAll()).thenReturn(List.of(existing));

            SystemSettingsForm urls = validForm();
            urls.setNoMatchingUrlPolicyDecision("AUTHENTICATED");
            service.updateSettings(urls);
            assertThat(existing.getNoMatchingUrlPolicyDecision()).isEqualTo("AUTHENTICATED");

            SystemSettingsForm methods = validForm();
            methods.setNoMatchingUrlPolicyDecision("PERMIT");
            methods.setMissingMethodPolicyDecision("AUTHENTICATED");
            assertThatThrownBy(() -> service.updateSettings(methods))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("missingMethodPolicyDecision");
            assertThat(existing.getNoMatchingUrlPolicyDecision()).as("nothing of a refused form is stored")
                    .isEqualTo("AUTHENTICATED");
            assertThat(existing.getMissingMethodPolicyDecision()).isEqualTo("PERMIT");
        }

        @Test
        @DisplayName("should store no-matching URL and missing method decisions")
        void storesNoPolicyDecisions() {
            SystemSettings existing = SystemSettings.builder().build();
            when(repository.findAll()).thenReturn(List.of(existing));

            SystemSettingsForm form = validForm();
            form.setPolicyCombiningAlgorithm("DENY_UNLESS_PERMIT");
            form.setNoMatchingUrlPolicyDecision("DENY");
            form.setMissingMethodPolicyDecision("DENY");

            service.updateSettings(form);

            verify(repository).save(existing);
            assertThat(existing.getPolicyCombiningAlgorithm()).isEqualTo("DENY_UNLESS_PERMIT");
            assertThat(existing.getNoMatchingUrlPolicyDecision()).isEqualTo("DENY");
            assertThat(existing.getMissingMethodPolicyDecision()).isEqualTo("DENY");
        }

        private SecurityZeroTrustProperties running(SecurityZeroTrustProperties.EnforcementMode mode) {
            SecurityZeroTrustProperties properties = new SecurityZeroTrustProperties();
            properties.setMode(mode);
            service.setZeroTrustProperties(properties);
            return properties;
        }

        private SystemSettings aRowWithMode(String mode) {
            SystemSettings row = SystemSettings.builder().securityZeroTrustMode(mode).build();
            when(repository.findAll()).thenReturn(List.of(row));
            return row;
        }

        private void saved(String mode) {
            SystemSettingsForm form = validForm();
            form.setSecurityZeroTrustMode(mode);
            service.updateSettings(form);
        }

        @Test
        @DisplayName("A save of another setting shows the mode in effect and does not store it as a choice")
        void theFormsOwnModeIsNoChoice() {
            running(SecurityZeroTrustProperties.EnforcementMode.ENFORCE);
            SystemSettings row = aRowWithMode(null);
            SystemSettingsForm form = validForm();
            form.setSecurityZeroTrustMode("ENFORCE");
            form.setMvcResourceScannerBasePackages("com.example.");

            service.updateSettings(form);

            verify(repository).save(row);
            assertThat(row.getSecurityZeroTrustMode()).isNull();
            assertThat(row.getMvcResourceScannerBasePackages()).isEqualTo("com.example.");
        }

        @ParameterizedTest
        @ValueSource(strings = {"enforce", " ENFORCE ", "Enforce"})
        @DisplayName("The mode in effect in another spelling is no choice either")
        void aSpellingOfTheModeInEffect(String submitted) {
            running(SecurityZeroTrustProperties.EnforcementMode.ENFORCE);
            SystemSettings row = aRowWithMode(null);

            saved(submitted);

            assertThat(row.getSecurityZeroTrustMode()).isNull();
        }

        @ParameterizedTest
        @NullSource
        @ValueSource(strings = {"", "   "})
        @DisplayName("A form that names no mode stores none: it used to store the built-in default")
        void aFormWithoutAMode(String submitted) {
            running(SecurityZeroTrustProperties.EnforcementMode.SHADOW);
            SystemSettings row = aRowWithMode(null);

            saved(submitted);

            assertThat(row.getSecurityZeroTrustMode()).isNull();
        }

        @ParameterizedTest
        @ValueSource(strings = {"", "  "})
        @DisplayName("A stored blank reads as not set, here as where the mode is applied")
        void aBlankStoredModeIsNotSet(String stored) {
            running(SecurityZeroTrustProperties.EnforcementMode.ENFORCE);
            SystemSettings row = aRowWithMode(stored);

            saved("ENFORCE");

            assertThat(row.getSecurityZeroTrustMode()).isEqualTo(stored);
        }

        @Test
        @DisplayName("A later deployment's mode is the one compared: the row stays free to follow the setting")
        void aLaterDeployment() {
            SecurityZeroTrustProperties properties = running(SecurityZeroTrustProperties.EnforcementMode.ENFORCE);
            SystemSettings row = aRowWithMode(null);

            saved("ENFORCE");
            properties.setMode(SecurityZeroTrustProperties.EnforcementMode.SHADOW);
            saved("SHADOW");

            assertThat(row.getSecurityZeroTrustMode()).isNull();
        }

        @Test
        @DisplayName("Another mode is the operator's choice and is stored")
        void anotherModeIsStored() {
            running(SecurityZeroTrustProperties.EnforcementMode.ENFORCE);
            SystemSettings row = aRowWithMode(null);

            saved("SHADOW");

            assertThat(row.getSecurityZeroTrustMode()).isEqualTo("SHADOW");
        }

        @Test
        @DisplayName("A mode already stored follows the form as before, the mode in effect included")
        void aStoredModeFollowsTheForm() {
            running(SecurityZeroTrustProperties.EnforcementMode.ENFORCE);
            SystemSettings row = aRowWithMode("SHADOW");

            saved("SHADOW");
            assertThat(row.getSecurityZeroTrustMode()).isEqualTo("SHADOW");

            saved("ENFORCE");
            assertThat(row.getSecurityZeroTrustMode()).as("back to the mode in effect").isEqualTo("ENFORCE");
        }

        @Test
        @DisplayName("A mode that does not exist is still refused, on an empty row too")
        void anUnknownModeIsRefused() {
            running(SecurityZeroTrustProperties.EnforcementMode.ENFORCE);
            SystemSettingsForm form = validForm();
            form.setSecurityZeroTrustMode("OFF-ISH");

            assertThatThrownBy(() -> service.updateSettings(form)).isInstanceOf(IllegalArgumentException.class);

            verify(repository, never()).save(any());
        }

        @Test
        @DisplayName("should store the submitted zero trust mode on a row whose mode is not set")
        void storesExplicitZeroTrustMode() {
            SystemSettings existing = SystemSettings.builder().securityZeroTrustMode(null).build();
            when(repository.findAll()).thenReturn(List.of(existing));

            SystemSettingsForm form = validForm();
            form.setSecurityZeroTrustMode("ENFORCE");

            service.updateSettings(form);

            verify(repository).save(existing);
            assertThat(existing.getSecurityZeroTrustMode()).isEqualTo("ENFORCE");
        }

        @Test
        @DisplayName("should reject values that are not enum constants without saving")
        void rejectsNonEnumValues() {
            SystemSettingsForm invalidUrlDecision = validForm();
            invalidUrlDecision.setNoMatchingUrlPolicyDecision("MAYBE");
            SystemSettingsForm lowerCaseMethodDecision = validForm();
            lowerCaseMethodDecision.setMissingMethodPolicyDecision("deny");
            SystemSettingsForm invalidAlgorithm = validForm();
            invalidAlgorithm.setPolicyCombiningAlgorithm("INVALID");
            SystemSettingsForm blankAlgorithm = validForm();
            blankAlgorithm.setPolicyCombiningAlgorithm(" ");

            for (SystemSettingsForm form : List.of(invalidUrlDecision, lowerCaseMethodDecision,
                    invalidAlgorithm, blankAlgorithm)) {
                assertThatThrownBy(() -> service.updateSettings(form))
                        .isInstanceOf(IllegalArgumentException.class);
            }
            verify(repository, never()).save(any(SystemSettings.class));
        }
    }

    private SystemSettingsForm validForm() {
        SystemSettingsForm form = new SystemSettingsForm();
        form.setAuditLogRetentionDays(90);
        form.setDefaultRole("ROLE_USER");
        form.setPolicyCombiningAlgorithm("FIRST_APPLICABLE");
        form.setRegistrationEnabled(false);
        form.setMvcResourceScannerBasePackages("io.contexa.contexaiam, io.contexa.contexaiamenterprise");
        return form;
    }
}
