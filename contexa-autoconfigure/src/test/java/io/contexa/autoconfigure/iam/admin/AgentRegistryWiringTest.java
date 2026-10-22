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

import io.contexa.autoconfigure.core.autonomous.CoreAutonomousAutoConfiguration;
import io.contexa.contexacore.autonomous.agent.AgentRegistry;
import io.contexa.contexacore.autonomous.agent.AgentRegistryRecorder;
import io.contexa.contexacore.autonomous.agent.InMemoryAgentRegistry;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexaiam.admin.web.agent.controller.AgentAdminController;
import io.contexa.contexaiam.agent.JdbcAgentRegistry;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.support.StaticMessageSource;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcOperations;

import java.nio.charset.StandardCharsets;
import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** A1-6: the registry is the database one when the Contexa database is there, and every agent request reaches it. */
class AgentRegistryWiringTest {

    @Test
    @SuppressWarnings("unchecked")
    void theRegistryIsKeptInTheContexaDatabaseWhenItIsThere() {
        ObjectProvider<JdbcOperations> withDatabase = mock(ObjectProvider.class);
        when(withDatabase.getIfAvailable()).thenReturn(mock(JdbcOperations.class));
        ObjectProvider<JdbcOperations> withoutDatabase = mock(ObjectProvider.class);

        IamAgentRegistryAutoConfiguration configuration = new IamAgentRegistryAutoConfiguration();

        assertThat(configuration.agentRegistry(withDatabase)).isInstanceOf(JdbcAgentRegistry.class);
        assertThat(configuration.agentRegistry(withoutDatabase)).isInstanceOf(InMemoryAgentRegistry.class);
        assertThat(configuration.agentAdminController(new InMemoryAgentRegistry(), new StaticMessageSource()))
                .isInstanceOf(AgentAdminController.class);
    }

    @Test
    void theDatabaseRegistryComesBeforeTheCoreDefault() throws Exception {
        assertThat(IamAgentRegistryAutoConfiguration.class.getAnnotation(AutoConfiguration.class).before())
                .containsExactly(CoreAutonomousAutoConfiguration.class);
        assertThat(CoreAutonomousAutoConfiguration.class.getDeclaredMethod("defaultAgentRegistry")
                .getAnnotation(ConditionalOnMissingBean.class).value()).containsExactly(AgentRegistry.class);
        assertThat(new ClassPathResource("META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports")
                .getContentAsString(StandardCharsets.UTF_8))
                .contains("io.contexa.autoconfigure.iam.admin.IamAgentRegistryAutoConfiguration");
    }

    @Test
    void theRecorderTakesTheConfiguredWriteInterval() {
        SecurityZeroTrustProperties properties = new SecurityZeroTrustProperties();
        properties.getAgent().setRegistryWriteInterval(Duration.ofSeconds(30));

        AgentRegistryRecorder recorder = new CoreAutonomousAutoConfiguration()
                .agentRegistryRecorder(new InMemoryAgentRegistry(), properties);

        assertThat(recorder).isNotNull();
        assertThat(properties.getAgent().getRegistryWriteInterval()).isEqualTo(Duration.ofSeconds(30));
    }
}
