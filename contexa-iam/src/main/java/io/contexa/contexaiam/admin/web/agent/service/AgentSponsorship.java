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
package io.contexa.contexaiam.admin.web.agent.service;

import io.contexa.contexacore.autonomous.agent.AgentRegistration;
import io.contexa.contexacore.autonomous.agent.AgentRegistry;
import io.contexa.contexacore.autonomous.agent.AgentStatus;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.lang.Nullable;
import org.springframework.util.StringUtils;

import java.util.List;
import java.util.function.Supplier;

/**
 * The agents a person is accountable for. An account that sponsors an agent still in service is not removed: the agent
 * would go on taking tokens with no one told when it acts unusually and no one to confirm its requests. The sponsor is
 * transferred, or the agent deregistered, first.
 */
public class AgentSponsorship {

    private final Supplier<AgentRegistry> registry;
    @Nullable
    private final MessageSource messages;

    /**
     * @param registry gives the agent registry, read at each call (it may be made after this), or null where agents are
     *                 not registered
     */
    public AgentSponsorship(Supplier<AgentRegistry> registry, @Nullable MessageSource messages) {
        this.registry = registry;
        this.messages = messages;
    }

    /** The identifiers of the agents in service (not deregistered) the person sponsors, in order. */
    public List<String> agentsSponsoredBy(@Nullable String username) {
        AgentRegistry agents = registry.get();
        if (agents == null || !StringUtils.hasText(username)) {
            return List.of();
        }
        String sponsor = username.trim();
        return agents.list(null, Integer.MAX_VALUE).stream()
                .filter(agent -> agent.status() != AgentStatus.DEREGISTERED && sponsor.equals(agent.sponsorId()))
                .map(AgentRegistration::agentId)
                .distinct()
                .sorted()
                .toList();
    }

    /**
     * Refuses the removal of an account that sponsors agents in service, naming them.
     *
     * @throws IllegalStateException with the text for the administrator
     */
    public void refuseRemovingTheSponsor(@Nullable String username) {
        List<String> agents = agentsSponsoredBy(username);
        if (agents.isEmpty()) {
            return;
        }
        String names = String.join(", ", agents);
        String fallback = "The account " + username + " is the sponsor of agents in service: " + names
                + ". Transfer their sponsor to another person or deregister them first.";
        throw new IllegalStateException(messages == null ? fallback : messages.getMessage(
                "admin.agents.sponsor.remove.refused", new Object[]{username, names}, fallback,
                LocaleContextHolder.getLocale()));
    }
}
