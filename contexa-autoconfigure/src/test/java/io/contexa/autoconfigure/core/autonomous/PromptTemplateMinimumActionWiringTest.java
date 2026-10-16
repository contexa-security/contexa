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
package io.contexa.autoconfigure.core.autonomous;

import io.contexa.contexacore.autonomous.context.decision.MinimumActionRules;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Arrays;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

/**
 * W4-4: the prompt template states the minimum action rules the host configured (contexa.security.zerotrust.
 * minimum-action.*), the same settings the strategies check.
 */
class PromptTemplateMinimumActionWiringTest {

    @Test
    void theTemplateStatesTheMinimumActionRulesTheHostConfigured() throws Exception {
        SecurityZeroTrustProperties zeroTrust = new SecurityZeroTrustProperties();
        zeroTrust.getMinimumAction().getIdentity().setEnabled(false);

        SecurityDecisionStandardPromptTemplate template = template(zeroTrust);

        Object sections = ReflectionTestUtils.getField(template, "promptSections");
        assertThat(ReflectionTestUtils.getField(sections, "minimumActionSettings"))
                .isEqualTo(zeroTrust.getMinimumAction().toRules())
                .isNotEqualTo(MinimumActionRules.Settings.DEFAULTS);
    }

    /**
     * N-CONF-1: a P3 floor the policy facts cannot meet (BLOCK) stops the start-up with the setting's name, instead of
     * turning every decision P3 hits into the technical fallback.
     */
    @Test
    void aP3FloorThePolicyFactsCannotMeetStopsTheStartUp() {
        SecurityZeroTrustProperties zeroTrust = new SecurityZeroTrustProperties();
        zeroTrust.getMinimumAction().getPolicySatisfaction().setAction("BLOCK");

        assertThatThrownBy(() -> template(zeroTrust))
                .isInstanceOf(InvocationTargetException.class)
                .cause()
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("contexa.security.zerotrust.minimum-action.policy-satisfaction.action");
    }

    private static SecurityDecisionStandardPromptTemplate template(SecurityZeroTrustProperties zeroTrust)
            throws Exception {
        Method method = Arrays.stream(CoreAutonomousAutoConfiguration.class.getDeclaredMethods())
                .filter(candidate -> candidate.getName().equals("securityDecisionStandardPromptTemplate"))
                .findFirst()
                .orElseThrow(() -> new AssertionError("Method not found: securityDecisionStandardPromptTemplate"));
        Object[] arguments = new Object[method.getParameterCount()];
        for (int i = 0; i < arguments.length; i++) {
            Class<?> type = method.getParameterTypes()[i];
            arguments[i] = type == SecurityZeroTrustProperties.class ? zeroTrust
                    : type == TieredStrategyProperties.class ? new TieredStrategyProperties()
                    : type == ObjectProvider.class ? mock(ObjectProvider.class)
                    : mock(type);
        }

        return (SecurityDecisionStandardPromptTemplate) method.invoke(new CoreAutonomousAutoConfiguration(), arguments);
    }
}
