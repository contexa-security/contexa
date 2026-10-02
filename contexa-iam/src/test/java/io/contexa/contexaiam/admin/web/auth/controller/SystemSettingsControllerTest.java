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

import io.contexa.contexacommon.entity.SystemSettings;
import io.contexa.contexacore.infra.redis.PolicyReloadBroadcaster;
import io.contexa.contexaiam.admin.web.auth.dto.SystemSettingsDtos.RoleOption;
import io.contexa.contexaiam.admin.web.auth.dto.SystemSettingsDtos.SystemSettingsForm;
import io.contexa.contexaiam.admin.web.auth.service.SystemSettingsRuntimeApplier;
import io.contexa.contexaiam.admin.web.auth.service.SystemSettingsService;
import io.contexa.contexaiam.security.xacml.pdp.combining.CombiningAlgorithm;
import io.contexa.contexaiam.security.xacml.pdp.combining.PolicyCombiningProperties.NoPolicyDecision;
import io.contexa.contexaiam.security.xacml.pep.CustomDynamicAuthorizationManager;
import org.junit.jupiter.api.BeforeEach;
import io.contexa.contexaiam.security.xacml.pdp.combining.PolicyCombiningProperties;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.context.MessageSource;
import org.springframework.ui.ConcurrentModel;
import org.springframework.ui.Model;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.servlet.mvc.support.RedirectAttributesModelMap;

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
    private MessageSource messageSource;
    @Mock
    private PolicyCombiningProperties policyCombiningProperties;


    @Mock
    private CustomDynamicAuthorizationManager authorizationManager;

    @Mock
    private SystemSettingsRuntimeApplier runtimeApplier;

    @Mock
    private PolicyReloadBroadcaster policyReloadBroadcaster;

    private SystemSettingsController controller;

    @BeforeEach
    void setUp() {
        when(messageSource.getMessage(anyString(), any(), any(Locale.class)))
                .thenAnswer(inv -> inv.getArgument(0));

        controller = new SystemSettingsController(systemSettingsService, policyCombiningProperties,
                messageSource, authorizationManager, runtimeApplier);
        controller.setPolicyReloadBroadcaster(policyReloadBroadcaster);
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

            RoleOption role = RoleOption.of("ROLE_USER", "Standard User");
            when(systemSettingsService.getDefaultRoleOptions()).thenReturn(List.of(role));

            Model model = new ConcurrentModel();
            String view = controller.showSettings(model);

            assertThat(view).isEqualTo("contexa/admin/system-settings");
            assertThat(model.getAttribute("activePage")).isEqualTo("system-settings");
            assertThat(model.getAttribute("settings")).isNotNull();
            assertThat(model.getAttribute("roles")).isNotNull();
            assertThat(model.getAttribute("algorithms")).isEqualTo(CombiningAlgorithm.values());
            assertThat(model.getAttribute("noPolicyDecisionOptions")).isEqualTo(NoPolicyDecision.values());
            assertThat(model.getAttribute("hcadModeOptions")).isNull();
        }

        @Test
        @DisplayName("should expose stored no-matching policy decisions on the form")
        void exposesStoredNoPolicyDecisions() {
            SystemSettings settings = SystemSettings.builder()
                    .noMatchingUrlPolicyDecision("DENY")
                    .missingMethodPolicyDecision("PERMIT")
                    .build();
            when(systemSettingsService.getSettings()).thenReturn(settings);
            when(systemSettingsService.getDefaultRoleOptions()).thenReturn(List.of());

            Model model = new ConcurrentModel();
            controller.showSettings(model);

            SystemSettingsForm form = (SystemSettingsForm) model.getAttribute("settings");
            assertThat(form.getNoMatchingUrlPolicyDecision()).isEqualTo("DENY");
            assertThat(form.getMissingMethodPolicyDecision()).isEqualTo("PERMIT");
        }
    }

    @Nested
    @DisplayName("updateSettings")
    class UpdateSettings {

        @Test
        @DisplayName("should save, apply stored settings, reload URL policies and broadcast to other instances")
        void success() {
            RedirectAttributes ra = new RedirectAttributesModelMap();
            SystemSettingsForm form = new SystemSettingsForm();
            form.setPolicyCombiningAlgorithm("DENY_OVERRIDES");
            form.setNoMatchingUrlPolicyDecision("DENY");
            form.setMissingMethodPolicyDecision("DENY");

            String view = controller.updateSettings(form, ra);

            assertThat(view).isEqualTo("redirect:/contexa/admin/system-settings");
            assertThat(ra.getFlashAttributes().get("message")).asString().contains("admin.system.settings.saved");

            InOrder order = inOrder(systemSettingsService, runtimeApplier, authorizationManager, policyReloadBroadcaster);
            order.verify(systemSettingsService).updateSettings(form);
            order.verify(runtimeApplier).apply();
            order.verify(authorizationManager).reload();
            order.verify(policyReloadBroadcaster).broadcastReload();
        }

        @Test
        @DisplayName("should not apply or broadcast when the service rejects a non-enum value")
        void invalidValueIsRejected() {
            RedirectAttributes ra = new RedirectAttributesModelMap();
            SystemSettingsForm form = new SystemSettingsForm();
            form.setNoMatchingUrlPolicyDecision("MAYBE");
            doThrow(new IllegalArgumentException("noMatchingUrlPolicyDecision has an unsupported value: MAYBE"))
                    .when(systemSettingsService).updateSettings(form);

            String view = controller.updateSettings(form, ra);

            assertThat(view).isEqualTo("redirect:/contexa/admin/system-settings");
            assertThat(ra.getFlashAttributes().get("errorMessage")).asString().contains("MAYBE");
            verify(runtimeApplier, never()).apply();
            verify(authorizationManager, never()).reload();
            verify(policyReloadBroadcaster, never()).broadcastReload();
        }

        @Test
        @DisplayName("should apply submitted values directly when no runtime applier is registered")
        void appliesSubmittedValuesWithoutRuntimeApplier() {
            PolicyCombiningProperties properties = new PolicyCombiningProperties();
            SystemSettingsController fallbackController = new SystemSettingsController(systemSettingsService,
                    properties, messageSource, authorizationManager, null);
            SystemSettingsForm form = new SystemSettingsForm();
            form.setPolicyCombiningAlgorithm("PERMIT_OVERRIDES");
            form.setNoMatchingUrlPolicyDecision("DENY");
            form.setMissingMethodPolicyDecision("DENY");

            fallbackController.updateSettings(form, new RedirectAttributesModelMap());

            assertThat(properties.getCombiningAlgorithm()).isEqualTo(CombiningAlgorithm.PERMIT_OVERRIDES);
            assertThat(properties.getNoMatchingUrlPolicyDecision()).isEqualTo(NoPolicyDecision.DENY);
            assertThat(properties.getMissingMethodPolicyDecision()).isEqualTo(NoPolicyDecision.DENY);
            verify(authorizationManager).setCombiningAlgorithm(CombiningAlgorithm.PERMIT_OVERRIDES);
            verify(authorizationManager).setNoMatchingUrlPolicyDecision(NoPolicyDecision.DENY);
            verify(authorizationManager).reload();
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
            verify(runtimeApplier, never()).apply();
        }
    }
}
