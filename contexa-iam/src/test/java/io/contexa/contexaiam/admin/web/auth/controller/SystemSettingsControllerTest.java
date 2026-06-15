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
package io.contexa.contexaiam.admin.web.auth.controller;

import io.contexa.contexacommon.entity.Role;
import io.contexa.contexacommon.entity.SystemSettings;
import io.contexa.contexacommon.repository.RoleRepository;
import io.contexa.contexaiam.admin.web.auth.dto.SystemSettingsDtos.SystemSettingsForm;
import io.contexa.contexaiam.admin.web.auth.service.SystemSettingsService;
import io.contexa.contexaiam.security.xacml.pdp.combining.CombiningAlgorithm;
import io.contexa.contexaiam.security.xacml.pep.CustomDynamicAuthorizationManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.context.MessageSource;
import org.springframework.ui.ConcurrentModel;
import org.springframework.ui.Model;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.servlet.mvc.support.RedirectAttributesModelMap;

import java.util.Collections;
import java.util.List;
import java.util.Locale;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@DisplayName("SystemSettingsController")
class SystemSettingsControllerTest {

    @Mock
    private SystemSettingsService systemSettingsService;

    @Mock
    private RoleRepository roleRepository;

    @Mock
    private MessageSource messageSource;

    @Mock
    private CustomDynamicAuthorizationManager authorizationManager;

    private SystemSettingsController controller;

    @BeforeEach
    void setUp() {
        when(messageSource.getMessage(anyString(), any(), any(Locale.class)))
                .thenAnswer(inv -> inv.getArgument(0));

        controller = new SystemSettingsController(systemSettingsService, roleRepository, messageSource, authorizationManager);
    }

    @Nested
    @DisplayName("showSettings")
    class ShowSettings {

        @Test
        @DisplayName("should populate model with activePage, settings, roles and combining algorithms")
        void success() {
            SystemSettings settings = SystemSettings.builder()
                    .defaultRole("ROLE_USER")
                    .policyCombiningAlgorithm("DENY_OVERRIDES")
                    .build();
            when(systemSettingsService.getSettings()).thenReturn(settings);

            Role role = Role.builder().roleName("ROLE_USER").roleDesc("Standard User").enabled(true).build();
            when(roleRepository.findAllRolesWithoutExpression()).thenReturn(List.of(role));

            Model model = new ConcurrentModel();
            String view = controller.showSettings(model);

            assertThat(view).isEqualTo("contexa/admin/system-settings");
            assertThat(model.getAttribute("activePage")).isEqualTo("system-settings");
            assertThat(model.getAttribute("settings")).isNotNull();
            assertThat(model.getAttribute("roles")).isNotNull();
            assertThat(model.getAttribute("algorithms")).isEqualTo(CombiningAlgorithm.values());
        }
    }

    @Nested
    @DisplayName("updateSettings")
    class UpdateSettings {

        @Test
        @DisplayName("should update settings and reload authorizationManager CombiningAlgorithm")
        void success() {
            RedirectAttributes ra = new RedirectAttributesModelMap();
            SystemSettingsForm form = new SystemSettingsForm();
            form.setPolicyCombiningAlgorithm("DENY_OVERRIDES");

            String view = controller.updateSettings(form, ra);

            assertThat(view).isEqualTo("redirect:/contexa/admin/system-settings");
            assertThat(ra.getFlashAttributes().get("message")).asString().contains("admin.system.settings.saved");

            verify(systemSettingsService).updateSettings(form);
            verify(authorizationManager).setCombiningAlgorithm(CombiningAlgorithm.DENY_OVERRIDES);
            verify(authorizationManager).reload();
        }

        @Test
        @DisplayName("should handle IllegalArgumentException when combining algorithm is invalid")
        void invalidAlgorithm() {
            RedirectAttributes ra = new RedirectAttributesModelMap();
            SystemSettingsForm form = new SystemSettingsForm();
            form.setPolicyCombiningAlgorithm("INVALID");

            String view = controller.updateSettings(form, ra);

            assertThat(view).isEqualTo("redirect:/contexa/admin/system-settings");
            verify(systemSettingsService).updateSettings(form);
            verify(authorizationManager, never()).setCombiningAlgorithm(any());
            verify(authorizationManager, never()).reload();
        }

        @Test
        @DisplayName("should flash error when updateSettings throws exception")
        void error() {
            RedirectAttributes ra = new RedirectAttributesModelMap();
            SystemSettingsForm form = new SystemSettingsForm();
            doThrow(new RuntimeException("DB error")).when(systemSettingsService).updateSettings(form);

            String view = controller.updateSettings(form, ra);

            assertThat(view).isEqualTo("redirect:/contexa/admin/system-settings");
            assertThat(ra.getFlashAttributes().get("errorMessage")).asString().contains("DB error");
        }
    }
}
