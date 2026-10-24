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

import io.contexa.contexacore.autonomous.context.support.ActionFamily;
import io.contexa.contexacore.autonomous.context.support.ActionFamilyResolver;
import org.springframework.lang.Nullable;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * How far an ALLOW in force answers an agent's later requests without a new decision (docs/agent F-1). A person's
 * requests seconds apart are one piece of work, so an ALLOW answers them for its validity; an agent sends a request
 * every second or two, and an ALLOW of its first read answered the enumeration of a whole customer list. For an agent
 * the ALLOW answers only the requests of the same operation as the request it decided, for a few resources and a few
 * requests; the next one is decided again, with the session's requests in its narrative.
 */
public class AgentAllowReuse {

    static final int CAPACITY = 10_000;
    static final Duration FORGET_AFTER = Duration.ofHours(1);

    /**
     * The operation of a request: the host's or the protected method's, else its path's words, else its method (a GET
     * of {@code /api/exports} is an export).
     */
    public static ActionFamily operation(@Nullable Map<String, ?> payload, @Nullable String resource) {
        Map<String, Object> declaredOnly = new HashMap<>();
        if (payload != null) {
            declaredOnly.putAll(payload);
            declaredOnly.remove("httpMethod");
            declaredOnly.remove("method");
        }
        ActionFamily declared = ActionFamilyResolver.resolve(declaredOnly).family();
        if (declared != ActionFamily.UNKNOWN) {
            return declared;
        }
        Object method = payload != null ? payload.get("httpMethod") : null;
        Object path = payload != null ? payload.get("requestPath") : null;
        return AgentScopeService.operation(method != null ? method.toString() : null,
                path != null ? path.toString() : resource);
    }

    /** The request a decision was made on, and what its ALLOW answered since. */
    private record Anchor(@Nullable String contextHash, ActionFamily operation, Set<String> resources, int requests,
                          Instant at) {
    }

    private final Map<String, Anchor> anchors = new ConcurrentHashMap<>();
    private final int maxRequests;
    private final int maxDistinctResources;
    private final Clock clock;

    public AgentAllowReuse(int maxRequests, int maxDistinctResources, @Nullable Clock clock) {
        this.maxRequests = Math.max(1, maxRequests);
        this.maxDistinctResources = Math.max(1, maxDistinctResources);
        this.clock = clock != null ? clock : Clock.systemUTC();
    }

    /** The agent's request is decided: its ALLOW, if it is one, answers the later requests like it. */
    public void decided(String subjectKey, @Nullable String contextHash, ActionFamily operation,
                        @Nullable String resource) {
        if (subjectKey == null) {
            return;
        }
        Set<String> resources = new HashSet<>();
        if (resource != null) {
            resources.add(resource);
        }
        if (anchors.size() >= CAPACITY) {
            Instant old = clock.instant().minus(FORGET_AFTER);
            anchors.values().removeIf(anchor -> anchor.at().isBefore(old));
        }
        anchors.put(subjectKey, new Anchor(contextHash, operation, resources, 1, clock.instant()));
    }

    /**
     * Whether the ALLOW in force answers this request of the agent: same context, same operation, and within the
     * resources and requests it may answer. An answered request counts.
     */
    public boolean answers(String subjectKey, @Nullable String contextHash, ActionFamily operation,
                           @Nullable String resource) {
        if (subjectKey == null) {
            return false;
        }
        boolean[] answered = new boolean[1];
        anchors.computeIfPresent(subjectKey, (key, anchor) -> {
            if (!Objects.equals(anchor.contextHash(), contextHash) || anchor.operation() != operation
                    || anchor.requests() >= maxRequests) {
                return anchor;
            }
            Set<String> resources = new HashSet<>(anchor.resources());
            if (resource != null) {
                resources.add(resource);
            }
            if (resources.size() > maxDistinctResources) {
                return anchor;
            }
            answered[0] = true;
            return new Anchor(anchor.contextHash(), operation, Set.copyOf(resources), anchor.requests() + 1,
                    anchor.at());
        });
        return answered[0];
    }
}
