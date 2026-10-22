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
import io.contexa.contexacore.autonomous.agent.InMemoryAgentRegistry;
import io.contexa.contexaiam.admin.web.agent.controller.AgentAdminController;
import io.contexa.contexaiam.agent.JdbcAgentRegistry;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.jdbc.core.JdbcOperations;

/**
 * A1-6: the agent registry kept in the Contexa database, and the console's agent screens. It runs before the core
 * configuration so its registry replaces the in-memory default; without the Contexa database the in-memory registry
 * is used here as well.
 */
@AutoConfiguration(before = CoreAutonomousAutoConfiguration.class)
public class IamAgentRegistryAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(AgentRegistry.class)
    public AgentRegistry agentRegistry(@Qualifier("contexaJdbcTemplate") ObjectProvider<JdbcOperations> jdbcOperations) {
        JdbcOperations operations = jdbcOperations.getIfAvailable();
        return operations != null ? new JdbcAgentRegistry(operations) : new InMemoryAgentRegistry();
    }

    @Bean
    @ConditionalOnMissingBean
    public AgentAdminController agentAdminController(AgentRegistry agentRegistry, MessageSource messageSource) {
        return new AgentAdminController(agentRegistry, messageSource);
    }
}
