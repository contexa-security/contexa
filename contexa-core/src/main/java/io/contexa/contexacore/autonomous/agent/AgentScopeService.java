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

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacommon.enums.AuditEventCategory;
import io.contexa.contexacommon.security.RequestPaths;
import io.contexa.contexacore.autonomous.audit.AuditRecord;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.context.support.ActionFamily;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.repository.ZeroTrustSubject;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;

import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * The narrowed scopes of agents (docs/agent A5-4): a decision on an agent's request narrows its later requests as the
 * {@link AgentScopeNarrower} says, and a request outside the scope in force is refused. A scope only narrows: a later
 * narrowing keeps only the operations both allow, and a scope ends only when its period ends. People are never
 * narrowed.
 */
@Slf4j
public class AgentScopeService {

    /** The step a narrowing adds to the decision record's enforcement (A5-5). */
    public static final String STEP = "SCOPE_NARROWED";
    static final int LIST_LIMIT = 500;

    private final AgentScopeStore store;
    private final AgentScopeNarrower narrower;
    private final CentralAuditFacade audit;
    private final Clock clock;

    public AgentScopeService(AgentScopeStore store, AgentScopeNarrower narrower, @Nullable CentralAuditFacade audit,
                             @Nullable Clock clock) {
        this.store = Objects.requireNonNull(store, "store");
        this.narrower = Objects.requireNonNull(narrower, "narrower");
        this.audit = audit;
        this.clock = clock != null ? clock : Clock.systemUTC();
    }

    /**
     * Narrows the agent's scope as the decision calls for.
     *
     * @return the step for the decision record, or empty when the decision narrows nothing
     */
    public Optional<String> onDecision(SecurityEvent event, ProcessingResult result) {
        ZeroTrustSubject subject = ZeroTrustSubject.of(event);
        if (subject == null || subject.agentId() == null) {
            return Optional.empty();
        }
        Optional<AgentScopeNarrower.Narrowing> narrowing = narrower.narrowing(subject, event, result);
        if (narrowing.isEmpty()) {
            return Optional.empty();
        }
        Instant now = clock.instant().truncatedTo(ChronoUnit.MICROS);
        Object requestId = event.getMetadata() != null ? event.getMetadata().get("requestId") : null;
        AgentScopeRestriction asked = new AgentScopeRestriction(subject.storageKey(), subject.tenantId(),
                subject.userId(), subject.agentId(), narrowing.get().allowed(), narrowing.get().reason(),
                requestId != null ? requestId.toString() : null, now, now.plus(narrowing.get().period()));
        AgentScopeRestriction kept = store.merge(subject.storageKey(), now,
                current -> current == null ? asked : current.narrowedBy(asked));
        record(subject, kept);
        return Optional.of(STEP + "(" + names(kept) + " until " + kept.until() + ")");
    }

    /** The scope in force for the subject, or empty. */
    public Optional<AgentScopeRestriction> inForce(ZeroTrustSubject subject) {
        if (subject == null || subject.agentId() == null) {
            return Optional.empty();
        }
        return store.find(subject.storageKey()).filter(scope -> scope.activeAt(clock.instant()));
    }

    /**
     * The scope that refuses the request, or empty when the request passes: no scope is in force, or it allows the
     * request's operation ({@link #operation}).
     */
    public Optional<AgentScopeRestriction> refusing(ZeroTrustSubject subject, String method, String path) {
        return inForce(subject).filter(scope -> !scope.allows(operation(method, path)));
    }

    /**
     * The operation of a request: the words of its path as the application routes it, weighed against its method
     * ({@link #weighed}). A path no router can read names none.
     */
    public static ActionFamily operation(@Nullable String method, @Nullable String path) {
        String routed = RequestPaths.routed(path);
        if (path != null && routed == null) {
            return ActionFamily.UNKNOWN;
        }
        ActionFamily named = ActionFamily.of(routed);
        return weighed(method, named != null ? named : ActionFamily.UNKNOWN);
    }

    /**
     * What the words of a path name, against the request's method: a word may name a graver operation than the method
     * ({@code GET /api/exports} is an export), never a lighter one. Only the method says a request reads, and a word
     * that says writing leaves a deletion a deletion. Without a method the words stand.
     */
    static ActionFamily weighed(@Nullable String method, ActionFamily named) {
        if (method == null) {
            return named;
        }
        ActionFamily byMethod = ActionFamily.of(method);
        ActionFamily stated = byMethod != null ? byMethod : ActionFamily.UNKNOWN;
        boolean lighter = named == ActionFamily.UNKNOWN || named == ActionFamily.READ
                || (named == ActionFamily.WRITE && stated == ActionFamily.DELETE);
        return lighter ? stated : named;
    }

    /** The scopes in force, for the console. */
    public List<AgentScopeRestriction> inForce() {
        return store.active(clock.instant(), LIST_LIMIT);
    }

    private void record(ZeroTrustSubject subject, AgentScopeRestriction kept) {
        if (audit == null) {
            return;
        }
        try {
            audit.recordSync(AuditRecord.builder()
                    .eventCategory(AuditEventCategory.AGENT_SCOPE_NARROWED)
                    .principalName("contexa")
                    .resourceIdentifier(subject.agentId())
                    .eventSource("CORE")
                    .action(STEP)
                    .decision(STEP)
                    .outcome(STEP)
                    .reason(kept.reason())
                    .subjectKind(subject.kind().name())
                    .agentId(subject.agentId())
                    .delegatorId(subject.delegatedAgent() ? subject.userId() : null)
                    .delegationId(subject.delegationId())
                    .tenantId(subject.tenantId())
                    .correlationId(kept.correlationId() != null && kept.correlationId().length() > 64
                            ? kept.correlationId().substring(0, 64) : kept.correlationId())
                    .details(Map.of("allowed", names(kept), "until", kept.until().toString()))
                    .build());
        } catch (RuntimeException e) {
            log.error("Agent scope narrowing audit failed: agentId={}", subject.agentId(), e);
        }
    }

    private static String names(AgentScopeRestriction scope) {
        return scope.allowed().isEmpty() ? "NONE"
                : scope.allowed().stream().map(Enum::name).sorted().collect(Collectors.joining(","));
    }
}
