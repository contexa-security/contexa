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
package io.contexa.autoconfigure.iam.aiam;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.std.labs.AILabFactory;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaiam.aiam.service.DataIngestionServiceImpl;
import io.contexa.contexaiam.aiam.strategy.ConditionTemplateDiagnosisStrategy;
import io.contexa.contexaiam.aiam.strategy.PolicyGenerationDiagnosisStrategy;
import io.contexa.contexaiam.aiam.strategy.ResourceNamingDiagnosisStrategy;
import io.contexa.contexaiam.repository.PolicyRepository;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class IamAiamServiceStrategyAutoConfigurationTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(IamAiamServiceStrategyAutoConfiguration.class))
            .withBean(PlatformConfig.class, () -> mock(PlatformConfig.class))
            .withBean(PolicyRepository.class, () -> mock(PolicyRepository.class))
            .withBean(ObjectMapper.class, ObjectMapper::new)
            .withBean(AILabFactory.class, () -> mock(AILabFactory.class));

    @Test
    void shouldStartWithoutVectorStoreAndSkipDataIngestionService() {
        contextRunner.run(context -> {
            assertThat(context).doesNotHaveBean(DataIngestionServiceImpl.class);
            assertThat(context).hasSingleBean(ConditionTemplateDiagnosisStrategy.class);
            assertThat(context).hasSingleBean(PolicyGenerationDiagnosisStrategy.class);
            assertThat(context).hasSingleBean(ResourceNamingDiagnosisStrategy.class);
        });
    }
}
