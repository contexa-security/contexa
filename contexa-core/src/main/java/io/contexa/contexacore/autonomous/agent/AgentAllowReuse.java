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
import io.contexa.contexacore.autonomous.context.support.ResourceImportanceResolver;
import io.contexa.contexacore.autonomous.utils.RequestFactRedaction;
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
 * requests; the next one is decided again, with the session's requests in its narrative. For a sensitive resource the
 * ALLOW answers fewer distinct resources (RL-5): a customer list is enumerated one record at a time, and every record
 * past the first is worth its own decision.
 * <p>
 * An agent has two anchors, one for the ALLOW of a sensitive resource and one for the ALLOW of a general one (RL-12).
 * They do not erase each other when decisions of both kinds come out together. The ALLOW of a general resource never
 * answers a sensitive one; the ALLOW of a sensitive resource answers general ones within the general limits, and those
 * do not use up what it keeps for its own sensitive resource. A decision recorded without its kind (the old call) keeps
 * the old behaviour: one anchor, the limit chosen by the request that asks.
 */
public class AgentAllowReuse {

    static final int CAPACITY = 10_000;
    static final Duration FORGET_AFTER = Duration.ofHours(1);
    /** The facts that hold the words of the protected URL: words of a path, weighed like the request's own. */
    private static final Set<String> URL_TEMPLATE_KEYS = Set.of("protectableResourceUrl", "resourceUrlTemplate");

    /**
     * The operation of a request: the host's or the protected method's, else its path's words, else its method (a GET
     * of {@code /api/exports} is an export). The words of a path never make a request lighter than its method says
     * ({@link AgentScopeService#weighed}): an ALLOW of a read answers no write.
     */
    public static ActionFamily operation(@Nullable Map<String, ?> payload, @Nullable String resource) {
        Map<String, Object> declaredOnly = new HashMap<>();
        if (payload != null) {
            declaredOnly.putAll(payload);
            declaredOnly.remove("httpMethod");
            declaredOnly.remove("method");
        }
        Object httpMethod = payload != null ? payload.get("httpMethod") : null;
        String method = httpMethod != null ? httpMethod.toString() : null;
        ActionFamilyResolver.Resolution declared = ActionFamilyResolver.resolve(declaredOnly);
        if (declared.family() != ActionFamily.UNKNOWN) {
            return URL_TEMPLATE_KEYS.contains(declared.sourceKey())
                    ? AgentScopeService.weighed(method, declared.family()) : declared.family();
        }
        Object path = payload != null ? payload.get("requestPath") : null;
        return AgentScopeService.operation(method, path != null ? path.toString() : resource);
    }

    /**
     * The request a decision was made on, and what its ALLOW answered since. {@code resources} are the resources of
     * the anchor's own kind; {@code covered} are the general resources a sensitive anchor answered besides.
     */
    private record Anchor(@Nullable String contextHash, ActionFamily operation, Set<String> resources,
                          Set<String> covered, int requests, Instant at) {
    }

    /** The anchors of a decision recorded without its kind (the old call). */
    private final Map<String, Anchor> anchors = new ConcurrentHashMap<>();
    private final Map<String, Anchor> sensitiveAnchors = new ConcurrentHashMap<>();
    private final Map<String, Anchor> generalAnchors = new ConcurrentHashMap<>();
    private final int maxRequests;
    private final int maxDistinctResources;
    private final int sensitiveMaxDistinctResources;
    private final Clock clock;

    /** The limits for a resource of any kind: a sensitive resource has the same limit as the others. */
    public AgentAllowReuse(int maxRequests, int maxDistinctResources, @Nullable Clock clock) {
        this(maxRequests, maxDistinctResources, maxDistinctResources, clock);
    }

    public AgentAllowReuse(int maxRequests, int maxDistinctResources, int sensitiveMaxDistinctResources,
                           @Nullable Clock clock) {
        this.maxRequests = Math.max(1, maxRequests);
        this.maxDistinctResources = Math.max(1, maxDistinctResources);
        this.sensitiveMaxDistinctResources = Math.max(1, Math.min(sensitiveMaxDistinctResources,
                this.maxDistinctResources));
        this.clock = clock != null ? clock : Clock.systemUTC();
    }

    /**
     * The resource of a request as the limits count it: its path, and for a sensitive resource its query as well, since
     * a record is often named by a value of the query ({@code /api/customers?id=7}) and the ALLOW of one answers no
     * other. A general resource stays its path: the pages of a list are one resource.
     */
    @Nullable
    public static String resource(@Nullable Map<String, ?> payload, @Nullable String resource) {
        Object query = payload != null ? payload.get(RequestFactRedaction.QUERY_REFERENCE) : null;
        return resource != null && query != null && sensitive(payload) ? resource + "?" + query : resource;
    }

    /**
     * Whether the request is for a sensitive resource: the importance the host declared on the protected method
     * (RL-14), else the sensitivity the resource declares or the request states, classified as SENSITIVE or CRITICAL.
     */
    public static boolean sensitive(@Nullable Map<String, ?> payload) {
        return ResourceImportanceResolver.sensitive(payload);
    }

    /** The agent's request is decided, kind not stated: its ALLOW, if it is one, answers the later requests like it. */
    public void decided(String subjectKey, @Nullable String contextHash, ActionFamily operation,
                        @Nullable String resource) {
        record(anchors, subjectKey, contextHash, operation, resource);
    }

    /**
     * The agent's request is decided, and whether it is for a sensitive resource is stated (RL-12): its ALLOW, if it
     * is one, becomes the anchor of its kind.
     */
    public void decided(String subjectKey, @Nullable String contextHash, ActionFamily operation,
                        @Nullable String resource, boolean sensitive) {
        record(sensitive ? sensitiveAnchors : generalAnchors, subjectKey, contextHash, operation, resource);
    }

    private void record(Map<String, Anchor> store, String subjectKey, @Nullable String contextHash,
                        ActionFamily operation, @Nullable String resource) {
        if (subjectKey == null) {
            return;
        }
        Set<String> resources = new HashSet<>();
        if (resource != null) {
            resources.add(resource);
        }
        if (store.size() >= CAPACITY) {
            Instant old = clock.instant().minus(FORGET_AFTER);
            store.values().removeIf(anchor -> anchor.at().isBefore(old));
        }
        store.put(subjectKey, new Anchor(contextHash, operation, resources, Set.of(), 1, clock.instant()));
    }

    /**
     * Whether the ALLOW in force answers this request of the agent: same context, same operation, and within the
     * resources and requests it may answer. An answered request counts.
     */
    public boolean answers(String subjectKey, @Nullable String contextHash, ActionFamily operation,
                           @Nullable String resource) {
        return answers(subjectKey, contextHash, operation, resource, false);
    }

    /** The same, with the limit of a sensitive resource when the request is for one (RL-5, RL-12). */
    public boolean answers(String subjectKey, @Nullable String contextHash, ActionFamily operation,
                           @Nullable String resource, boolean sensitive) {
        return answers(subjectKey, contextHash, operation, resource, sensitive, true);
    }

    /**
     * Whether the ALLOW that was just decided answers a request that joined it while it was being decided (RL-12). It
     * asked the same question as the request that began the decision, so the request limit does not count it and it
     * leaves that limit untouched for the requests that come later; the limits of the resources, the operation and the
     * context hold as for any request.
     */
    public boolean answersJoined(String subjectKey, @Nullable String contextHash, ActionFamily operation,
                                 @Nullable String resource, boolean sensitive) {
        return answers(subjectKey, contextHash, operation, resource, sensitive, false);
    }

    private boolean answers(String subjectKey, @Nullable String contextHash, ActionFamily operation,
                            @Nullable String resource, boolean sensitive, boolean counted) {
        if (subjectKey == null) {
            return false;
        }
        if (sensitive) {
            // The ALLOW of a general resource never answers a sensitive one.
            return answerSame(sensitiveAnchors, subjectKey, contextHash, operation, resource,
                    sensitiveMaxDistinctResources, true, counted)
                    || answerSame(anchors, subjectKey, contextHash, operation, resource,
                    sensitiveMaxDistinctResources, false, counted);
        }
        return answerSame(generalAnchors, subjectKey, contextHash, operation, resource, maxDistinctResources, false,
                counted)
                || answerGeneralBySensitive(subjectKey, contextHash, operation, resource, counted)
                || answerSame(anchors, subjectKey, contextHash, operation, resource, maxDistinctResources, false,
                counted);
    }

    /**
     * The anchor of the request's own kind. A sensitive request is answered only by an anchor that names the sensitive
     * resource it decided ({@code needsNamedResource}): one that names none cannot say which record it allowed.
     */
    private boolean answerSame(Map<String, Anchor> store, String subjectKey, @Nullable String contextHash,
                               ActionFamily operation, @Nullable String resource, int distinctLimit,
                               boolean needsNamedResource, boolean counted) {
        boolean[] answered = new boolean[1];
        store.computeIfPresent(subjectKey, (key, anchor) -> {
            if (!matches(anchor, contextHash, operation, counted)
                    || (needsNamedResource && anchor.resources().isEmpty())) {
                return anchor;
            }
            Set<String> resources = new HashSet<>(anchor.resources());
            if (resource != null) {
                resources.add(resource);
            }
            if (resources.size() > distinctLimit) {
                return anchor;
            }
            answered[0] = true;
            return new Anchor(anchor.contextHash(), operation, Set.copyOf(resources), anchor.covered(),
                    anchor.requests() + (counted ? 1 : 0), anchor.at());
        });
        return answered[0];
    }

    /** The ALLOW of a sensitive resource answering a general one, within the general limits. */
    private boolean answerGeneralBySensitive(String subjectKey, @Nullable String contextHash, ActionFamily operation,
                                             @Nullable String resource, boolean counted) {
        boolean[] answered = new boolean[1];
        sensitiveAnchors.computeIfPresent(subjectKey, (key, anchor) -> {
            if (!matches(anchor, contextHash, operation, counted)) {
                return anchor;
            }
            Set<String> covered = new HashSet<>(anchor.covered());
            if (resource != null) {
                covered.add(resource);
            }
            if (covered.size() > maxDistinctResources) {
                return anchor;
            }
            answered[0] = true;
            return new Anchor(anchor.contextHash(), operation, anchor.resources(), Set.copyOf(covered),
                    anchor.requests() + (counted ? 1 : 0), anchor.at());
        });
        return answered[0];
    }

    private boolean matches(Anchor anchor, @Nullable String contextHash, ActionFamily operation, boolean counted) {
        return Objects.equals(anchor.contextHash(), contextHash) && anchor.operation() == operation
                && (!counted || anchor.requests() < maxRequests);
    }
}
