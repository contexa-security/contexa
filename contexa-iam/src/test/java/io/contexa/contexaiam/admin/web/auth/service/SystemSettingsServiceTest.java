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
import io.contexa.contexaiam.admin.web.auth.dto.SystemSettingsDtos.SystemSettingsForm;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
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
