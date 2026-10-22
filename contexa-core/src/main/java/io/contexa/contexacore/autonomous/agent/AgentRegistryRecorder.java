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
package io.contexa.contexacore.autonomous.agent;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.contexa.contexacommon.security.subject.SubjectKind;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;

import java.time.Duration;
import java.util.Map;

/**
 * Records every agent request in the {@link AgentRegistry} (A1-6), so an agent is known from its first request, with
 * its tenant, subject kind and client. The same agent is written at most once an interval; a failed write is logged
 * and retried with the next request, and never fails the request.
 */
@Slf4j
public class AgentRegistryRecorder {

    private static final int MAX_TRACKED_AGENTS = 10_000;

    private final AgentRegistry registry;
    private final Cache<String, Boolean> recentlyRecorded;

    public AgentRegistryRecorder(AgentRegistry registry, Duration writeInterval) {
        this.registry = registry;
        Duration interval = writeInterval != null && !writeInterval.isNegative() ? writeInterval : Duration.ofMinutes(1);
        this.recentlyRecorded = Caffeine.newBuilder()
                .expireAfterWrite(interval)
                .maximumSize(MAX_TRACKED_AGENTS)
                .build();
    }

    @EventListener
    public void onZeroTrustEvent(ZeroTrustSpringEvent event) {
        Map<String, Object> payload = event != null ? event.getPayload() : null;
        if (payload == null || !agent(payload.get("executionSubjectKind"))) {
            return;
        }
        String agentId = text(payload.get("agentId"));
        if (agentId == null) {
            return;
        }
        String tenantId = firstText(payload.get("tenantId"), payload.get("organizationId"));
        String key = AgentRegistrations.tenantKey(tenantId) + "\u0000" + agentId;
        if (recentlyRecorded.getIfPresent(key) != null) {
            return;
        }
        try {
            registry.observe(new AgentSighting(tenantId, agentId, text(payload.get("executionSubjectKind")),
                    firstText(payload.get("delegationTokenClientId"), payload.get("clientId")), event.getEventTimestamp()));
            recentlyRecorded.put(key, Boolean.TRUE);
        } catch (RuntimeException ex) {
            log.warn("Agent registry could not record agent {}: {}", agentId, ex.getMessage(), ex);
        }
    }

    private static boolean agent(Object kind) {
        String text = text(kind);
        if (text == null) {
            return false;
        }
        try {
            return SubjectKind.valueOf(text).agent();
        } catch (IllegalArgumentException unknownKind) {
            return false;
        }
    }

    private static String firstText(Object... values) {
        for (Object value : values) {
            String text = text(value);
            if (text != null) {
                return text;
            }
        }
        return null;
    }

    private static String text(Object value) {
        if (value == null) {
            return null;
        }
        String text = value.toString().trim();
        return text.isEmpty() ? null : text;
    }
}
