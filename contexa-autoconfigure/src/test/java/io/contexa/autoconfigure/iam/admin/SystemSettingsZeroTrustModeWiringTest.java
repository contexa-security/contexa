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
package io.contexa.autoconfigure.iam.admin;

import io.contexa.contexacommon.repository.RoleRepository;
import io.contexa.contexacommon.repository.SystemSettingsRepository;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexaiam.admin.web.auth.service.SystemSettingsService;
import io.contexa.contexaiam.security.xacml.pdp.combining.PolicyCombiningProperties;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/** The service is told the mode and the URL decision in effect, or it stores the ones the form shows, as it did. */
class SystemSettingsZeroTrustModeWiringTest {

    @Test
    @DisplayName("the service compares a submitted mode with the settings of the application")
    void theServiceKnowsTheModeInEffect() {
        SecurityZeroTrustProperties properties = new SecurityZeroTrustProperties();
        StaticListableBeanFactory beans = new StaticListableBeanFactory();
        beans.addBean("properties", properties);

        SystemSettingsService service = new IamAdminPasswordPolicyAutoConfiguration().systemSettingsService(
                mock(SystemSettingsRepository.class), mock(RoleRepository.class),
                beans.getBeanProvider(SecurityZeroTrustProperties.class),
                beans.getBeanProvider(PolicyCombiningProperties.class));

        assertThat(ReflectionTestUtils.getField(service, "zeroTrustProperties")).isSameAs(properties);
        assertThat(ReflectionTestUtils.getField(service, "policyCombiningProperties")).isNull();
    }

    @Test
    @DisplayName("the service compares a submitted URL decision with the one the application runs")
    void theServiceKnowsTheUrlDecisionInEffect() {
        PolicyCombiningProperties properties = new PolicyCombiningProperties();
        StaticListableBeanFactory beans = new StaticListableBeanFactory();
        beans.addBean("policy", properties);

        SystemSettingsService service = new IamAdminPasswordPolicyAutoConfiguration().systemSettingsService(
                mock(SystemSettingsRepository.class), mock(RoleRepository.class),
                beans.getBeanProvider(SecurityZeroTrustProperties.class),
                beans.getBeanProvider(PolicyCombiningProperties.class));

        assertThat(ReflectionTestUtils.getField(service, "policyCombiningProperties")).isSameAs(properties);
    }
}
