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
package io.contexa.contexaiam.properties;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("IamAdminProperties binding")
class IamAdminPropertiesBindingTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withUserConfiguration(Config.class);

    @Test
    @DisplayName("condition-templates.enabled defaults to false when no property is provided")
    void conditionTemplatesEnabled_defaultsToFalse() {
        contextRunner.run(context -> {
            IamAdminProperties properties = context.getBean(IamAdminProperties.class);

            assertThat(properties.getConditionTemplates()).isNotNull();
            assertThat(properties.getConditionTemplates().isEnabled())
                    .as("condition-templates must be opt-in; default must be false")
                    .isFalse();
        });
    }

    @Test
    @DisplayName("condition-templates.enabled=true binds via YAML kebab-case property")
    void conditionTemplatesEnabled_true_bindsCorrectly() {
        contextRunner
                .withPropertyValues("contexa.iam.admin.condition-templates.enabled=true")
                .run(context -> {
                    IamAdminProperties properties = context.getBean(IamAdminProperties.class);
                    assertThat(properties.getConditionTemplates().isEnabled()).isTrue();
                });
    }

    @Test
    @DisplayName("condition-templates.enabled=false binds explicitly")
    void conditionTemplatesEnabled_false_bindsCorrectly() {
        contextRunner
                .withPropertyValues("contexa.iam.admin.condition-templates.enabled=false")
                .run(context -> {
                    IamAdminProperties properties = context.getBean(IamAdminProperties.class);
                    assertThat(properties.getConditionTemplates().isEnabled()).isFalse();
                });
    }

    @EnableConfigurationProperties(IamAdminProperties.class)
    static class Config {
    }
}
