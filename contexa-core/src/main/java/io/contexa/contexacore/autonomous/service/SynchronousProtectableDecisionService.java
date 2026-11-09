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
package io.contexa.contexacore.autonomous.service;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.security.subject.SubjectKind;
import io.contexa.contexacommon.store.ContexaStores;
import io.contexa.contexacommon.store.StoreFailures;
import io.contexa.contexacommon.store.StoreUnavailableException;
import io.contexa.contexacore.autonomous.SecurityPlaneAgent;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.SecurityEventContext;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import io.contexa.contexacore.autonomous.event.listener.ZeroTrustEventListener;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexacore.autonomous.event.support.ZeroTrustSecurityEventConverter;
import io.contexa.contexacore.autonomous.handler.handler.SecurityDecisionEnforcementHandler;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.audit.AgentDecisionRecord;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionPrecedence;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustSubject;
import io.contexa.contexacore.autonomous.store.ExpiringKeySpace;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacommon.security.bridge.AgentRequestConfirmation;
import io.contexa.contexacore.autonomous.agent.AgentAllowReuse;
import io.contexa.contexacore.autonomous.agent.AgentDecisionFlights;
import io.contexa.contexacore.autonomous.context.support.ResourceImportanceResolver;
import io.contexa.contexacore.autonomous.execution.ZeroTrustAccessDeniedException;
import java.time.Clock;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BooleanSupplier;
import lombok.extern.slf4j.Slf4j;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.security.core.Authentication;
import org.springframework.util.StringUtils;

@Slf4j
public class SynchronousProtectableDecisionService {

    /**
     * Q-23: how long a sensitive request waits for its verdict while the analysis is behind: the three seconds a request
     * of a synchronous {@code @Protectable} is meant to take. It is the wait of one request, on a resource the host called
     * sensitive, and only then.
     */
    private static final Duration DEFAULT_BEHIND_WAIT = Duration.ofSeconds(3);
    private static final long VERDICT_POLL_MS = 100L;
    private static final int STORE_RETRY_AFTER_SECONDS = 5;
    private static final int WAITING_ROOM_RETRY_AFTER_SECONDS = 5;
    /**
     * How long a changed context whose verdict did not come in time is not waited for again. A model that has stopped
     * answering would otherwise hold each of its calls for the whole wait, which stops the application for that user.
     */
    private static final Duration UNANSWERED_CONTEXT_PAUSE = Duration.ofSeconds(60);
    private static final int UNANSWERED_CONTEXTS_KEPT = 10_000;
    /** A context that asked for a place in the limit is remembered for the window of the limit and a margin. */
    private static final Duration CONTEXT_OF_THE_LIMIT_KEPT = Duration.ofMinutes(5);
    private static final int CONTEXTS_OF_THE_LIMIT_KEPT = 20_000;
    /**
     * How long the analysis of a held context counts as started: the time the model may take, and a margin. A context
     * still undecided after it is asked about again, as one whose analysis was lost.
     */
    private static final Duration CONTEXT_ASKED_ABOUT_KEPT = Duration.ofSeconds(90);
    /** What a request turned away for its context is told: when the verdict is expected, a few seconds. */
    private static final int CHANGED_CONTEXT_RETRY_AFTER_SECONDS = 5;
    /**
     * Q-7: how long a verdict may still come while a store is down. The analysis runs on the application's own client,
     * which waits far longer than a request should, so the request stops waiting for it; a verdict that comes in this
     * time still answers, as a restriction the store did not take does.
     */
    private static final Duration DEFAULT_STORE_DOWN_WAIT = Duration.ofSeconds(3);

    private final ZeroTrustEventPublisher zeroTrustEventPublisher;
    private final ZeroTrustEventListener zeroTrustEventListener;
    private final SecurityPlaneAgent securityPlaneAgent;
    private final ZeroTrustActionRepository actionRepository;
    private UnanalysedRequestRecorder unanalysedRequestRecorder;
    private AgentAllowReuse agentAllowReuse;
    private AgentDecisionFlights agentDecisionFlights;
    private SecurityZeroTrustProperties.UnrecordedAgentRequest unrecordedAgentRequest =
            SecurityZeroTrustProperties.UnrecordedAgentRequest.DECIDE_IN_PLACE;
    private Duration decisionWait;
    private Duration behindWait = DEFAULT_BEHIND_WAIT;
    private Duration storeDownWait = DEFAULT_STORE_DOWN_WAIT;
    private BooleanSupplier enforcing = () -> true;
    private ContexaStores contexaStores = new ContexaStores();
    /** The verdicts this server is reaching for changed contexts, one for each subject and context. */
    private final Map<String, VerdictUnderWay> changedContextVerdicts = new ConcurrentHashMap<>();
    private ExpiringKeySpace<Boolean> unansweredContexts = unansweredContexts(Clock.systemUTC());
    /** The contexts that asked for a place in the limit of new contexts, and whether they found one. */
    private ExpiringKeySpace<Boolean> contextsOfTheLimit = contextsOfTheLimit(Clock.systemUTC());
    /** The changed contexts whose analysis a held request has started: one for each, however many calls are turned away. */
    private ExpiringKeySpace<Boolean> contextsAskedAbout = contextsAskedAbout(Clock.systemUTC());
    private NewContextDecisionLimit newContextDecisionLimit;

    public SynchronousProtectableDecisionService(
            ZeroTrustEventPublisher zeroTrustEventPublisher,
            ZeroTrustEventListener zeroTrustEventListener,
            SecurityPlaneAgent securityPlaneAgent,
            ZeroTrustActionRepository actionRepository) {
        this.zeroTrustEventPublisher = zeroTrustEventPublisher;
        this.zeroTrustEventListener = zeroTrustEventListener;
        this.securityPlaneAgent = securityPlaneAgent;
        this.actionRepository = actionRepository;
    }

    public void setUnanalysedRequestRecorder(UnanalysedRequestRecorder unanalysedRequestRecorder) {
        this.unanalysedRequestRecorder = unanalysedRequestRecorder;
    }

    /**
     * The decisions of a new context a person may ask for in a short window, which the calls of a changed context take
     * from with the person's sign-ins; without it every changed context is analysed.
     */
    public void setNewContextDecisionLimit(NewContextDecisionLimit newContextDecisionLimit) {
        this.newContextDecisionLimit = newContextDecisionLimit;
    }

    /** PR-54: the longest a synchronous decision holds the request's thread; null analyses in the request. */
    public void setDecisionWait(Duration decisionWait) {
        this.decisionWait = decisionWait != null && !decisionWait.isZero() && !decisionWait.isNegative()
                ? decisionWait : null;
    }

    /** Measures the pause of a changed context with {@code clock}. */
    void setClock(Clock clock) {
        this.unansweredContexts = unansweredContexts(clock);
        this.contextsOfTheLimit = contextsOfTheLimit(clock);
        this.contextsAskedAbout = contextsAskedAbout(clock);
    }

    private static ExpiringKeySpace<Boolean> contextsAskedAbout(Clock clock) {
        return ExpiringKeySpace.<Boolean>builder(clock).ttl(CONTEXT_ASKED_ABOUT_KEPT).bound(CONTEXTS_OF_THE_LIMIT_KEPT).build();
    }

    private static ExpiringKeySpace<Boolean> contextsOfTheLimit(Clock clock) {
        return ExpiringKeySpace.<Boolean>builder(clock).ttl(CONTEXT_OF_THE_LIMIT_KEPT).bound(CONTEXTS_OF_THE_LIMIT_KEPT).build();
    }

    private static ExpiringKeySpace<Boolean> unansweredContexts(Clock clock) {
        return ExpiringKeySpace.<Boolean>builder(clock).ttl(UNANSWERED_CONTEXT_PAUSE).bound(UNANSWERED_CONTEXTS_KEPT).build();
    }

    /** Q-7: how long a verdict may still come while a store is down. */
    void setStoreDownWait(Duration storeDownWait) {
        this.storeDownWait = storeDownWait;
    }

    /** Q-23: how long a sensitive request waits for its verdict while the analysis is behind. */
    void setBehindWait(Duration behindWait) {
        this.behindWait = behindWait;
    }

    /** Q-23: whether decisions are enforced; where they are not nothing is held for one. */
    public void setEnforcing(BooleanSupplier enforcing) {
        this.enforcing = enforcing != null ? enforcing : () -> true;
    }

    public void setContexaStores(ContexaStores contexaStores) {
        this.contexaStores = contexaStores;
    }

    public SyncDecisionResult analyze(MethodInvocation methodInvocation, Authentication authentication) {
        return analyze(zeroTrustEventPublisher.buildMethodAuthorizationEvent(
                methodInvocation,
                authentication,
                true,
                null
        ));
    }

    /**
     * docs/agent B4: decides an authorization event as a synchronous {@code @Protectable} is decided: a restriction
     * in force answers it without analysis, else it is analysed in place.
     */
    public SyncDecisionResult analyze(ZeroTrustSpringEvent event) {
        String userId = event.getUserId();
        String contextBindingHash = zeroTrustEventListener.generateAuthorizationContextBindingHash(event);

        // docs/agent A7-2: a synchronous request is decided itself; only a restriction in force answers it.
        if (zeroTrustEventListener.shouldPublishSynchronousAuthorizationEvent(event)) {
            if (flightsApply(event)) {
                return analyzeInFlight(event, userId, contextBindingHash);
            }
            return decideInPlace(event, userId, contextBindingHash);
        }

        // The restriction in force answers the request without analysis; its session still keeps it (N-SES-1).
        SyncDecisionResult result = currentResult(event, userId, contextBindingHash, null);
        recordUnanalysed(event, result.action());
        return result;
    }

    /** The analysis of one request, in the request's own thread. */
    private SyncDecisionResult decideInPlace(ZeroTrustSpringEvent event, String userId, String contextBindingHash) {
        try {
            return verdictOf(event, userId, contextBindingHash);
        } catch (DecisionNotInTimeException notInTime) {
            return withoutAVerdict(event, userId, contextBindingHash);
        }
    }

    /**
     * The verdict of one request.
     *
     * @throws DecisionNotInTimeException when the verdict did not come in time, or there is no room for the analysis
     */
    private SyncDecisionResult verdictOf(ZeroTrustSpringEvent event, String userId, String contextBindingHash) {
        SecurityEvent securityEvent = ZeroTrustSecurityEventConverter.convert(event);
        // The engine takes the request in here, as a collector does for an analysis it queues (Q-15).
        securityEvent.addMetadata(DeletedAccountWriteFence.TAKEN_IN_AT, System.currentTimeMillis());
        SecurityEventContext processingContext;
        try {
            processingContext = decidedInTime(securityEvent);
        } catch (DecisionNotInTimeException notInTime) {
            throw notInTime;
        } catch (RuntimeException failure) {
            ZeroTrustAction decided = decidedButNotKept(securityEvent);
            if (decided != null && decided.isAccessRestricted()) {
                // The model restricted the request and the store did not take it: the restriction answers this request.
                return new SyncDecisionResult(event, contextBindingHash, decided, null, null);
            }
            if (decided == null && !StoreFailures.isStoreFailure(failure)) {
                throw failure;
            }
            throw undecided(event, failure);
        }
        agentDecided(event, contextBindingHash);
        SyncDecisionResult result = currentResult(event, userId, contextBindingHash, processingContext);
        if (result.action() == ZeroTrustAction.PENDING_ANALYSIS && contexaStores.anyDown()) {
            throw undecided(event, null);
        }
        return result;
    }

    /** The decision the enforcement kept on the event because the store did not take its record, or null. */
    private static ZeroTrustAction decidedButNotKept(SecurityEvent securityEvent) {
        Object kept = securityEvent.getMetadata() != null
                ? securityEvent.getMetadata().get(SecurityDecisionEnforcementHandler.AUDIT_PENDING_PROCESSING_RESULT) : null;
        return kept instanceof ProcessingResult result && StringUtils.hasText(result.getAction())
                ? ZeroTrustAction.fromString(result.getAction()) : null;
    }

    /**
     * A store kept this request from being decided. A person's protected call goes on then, as the operating mode
     * specifies; an agent is never let through without a verdict (A1-5, RL-12), so it is refused as busy.
     */
    private RuntimeException undecided(ZeroTrustSpringEvent event, RuntimeException failure) {
        if (agentRequest(event)) {
            return ZeroTrustAccessDeniedException.analysisBusy(event.getResource(), STORE_RETRY_AFTER_SECONDS);
        }
        StoreUnavailableException unavailable = new StoreUnavailableException("The store of Contexa's decisions");
        if (failure != null) {
            unavailable.addSuppressed(failure);
        }
        return unavailable;
    }

    /**
     * PR-54: the analysis, for as long as the request may wait for it. Past the wait it goes on by itself on the
     * analysis threads and stores its decision for the next request, so a model that does not answer does not hold the
     * application's thread for as long as the model is given.
     *
     * @throws DecisionNotInTimeException when the verdict did not come in time, or there is no room for the analysis
     */
    private SecurityEventContext decidedInTime(SecurityEvent securityEvent) {
        Duration wait = decisionWait;
        if (wait == null) {
            return securityPlaneAgent.processSecurityEvent(securityEvent);
        }
        try {
            return verdictInTime(securityPlaneAgent.processSecurityEventOffThread(securityEvent), wait);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new DecisionNotInTimeException();
        } catch (ExecutionException failed) {
            if (failed.getCause() instanceof RejectedExecutionException) {
                throw new DecisionNotInTimeException();
            }
            if (failed.getCause() instanceof RuntimeException failure) {
                throw failure;
            }
            if (failed.getCause() instanceof Error error) {
                throw error;
            }
            throw new IllegalStateException("The analysis of a synchronous request failed", failed.getCause());
        }
    }

    /**
     * The answer to a synchronous request whose verdict did not come in time: it is not let through without one, an
     * ALLOW of an earlier request says nothing of it, and a stricter decision that landed meanwhile answers it. The
     * answer is this request's: nothing is stored, the analysis still decides. An agent is told the engine is busy, as
     * it is when the flights have no place for it (RL-12).
     */
    private SyncDecisionResult withoutAVerdict(ZeroTrustSpringEvent event, String userId, String contextBindingHash) {
        ZeroTrustAction inForce = currentAction(event, userId, contextBindingHash);
        if ((inForce == null || !inForce.isAccessRestricted()) && contexaStores.anyDown()) {
            // Q-7: the store held the analysis back, which says nothing of the request.
            throw undecided(event, null);
        }
        boolean restricted = inForce == ZeroTrustAction.BLOCK || inForce == ZeroTrustAction.ESCALATE;
        if (!restricted && agentRequest(event)) {
            throw ZeroTrustAccessDeniedException.analysisBusy(event.getResource(),
                    (int) Math.max(1, decisionWait.toSeconds()));
        }
        return new SyncDecisionResult(event, contextBindingHash, restricted ? inForce : ZeroTrustAction.CHALLENGE,
                actionRepository.getAnalysisData(decisionKey(event, userId)), null);
    }

    /** The verdict within the wait, or within the shorter one from the moment a store is seen down. */
    private <T> T verdictInTime(Future<T> verdict, Duration wait) throws InterruptedException, ExecutionException {
        long left = wait.toMillis();
        long leftWhileDown = storeDownWait.toMillis();
        while (true) {
            long slice = Math.max(1L, Math.min(VERDICT_POLL_MS, left));
            try {
                return verdict.get(slice, TimeUnit.MILLISECONDS);
            } catch (TimeoutException stillRunning) {
                left -= slice;
                leftWhileDown = contexaStores.anyDown() ? leftWhileDown - slice : storeDownWait.toMillis();
                if (left <= 0 || leftWhileDown <= 0) {
                    throw new DecisionNotInTimeException();
                }
            }
        }
    }

    /** Whether the flights take this request: an agent's request, with the flights on. */
    private boolean flightsApply(ZeroTrustSpringEvent event) {
        return agentDecisionFlights != null && agentDecisionFlights.enabled() && agentRequest(event);
    }

    /**
     * docs/agent RL-12: an agent's request decided in place goes through the flights. The same question asked by many
     * requests at once is analysed once, the analyses one agent has running are limited, and a restriction stored while
     * the request waits, or right before it would be released, answers it. A request the engine has no place or time for
     * is refused as busy; it is never let through without a verdict.
     */
    private SyncDecisionResult analyzeInFlight(ZeroTrustSpringEvent event, String userId, String contextBindingHash) {
        AgentDecisionFlights.Request request = flightRequest(event, userId, contextBindingHash);
        AgentDecisionFlights.Result<SyncDecisionResult> result;
        try {
            result = agentDecisionFlights.execute(request, ground(event, userId, contextBindingHash),
                    () -> decideInPlace(event, userId, contextBindingHash));
        } catch (RuntimeException failure) {
            throw failure;
        } catch (Exception failure) {
            throw new IllegalStateException("The decision of an agent's request failed", failure);
        }
        switch (result.kind()) {
            case LED:
                return result.value();
            case FAILED:
                if (result.failure() instanceof RuntimeException failure) {
                    throw failure;
                }
                throw new IllegalStateException("The decision this request waited for failed", result.failure());
            case BUSY:
                throw ZeroTrustAccessDeniedException.analysisBusy(event.getResource(),
                        (int) Math.max(1, agentDecisionFlights.settings().maxWait().toSeconds()));
            case COVERED:
            case RESTRICTED:
            default:
                // Answered by the decision in force, not analysed: its session still keeps it (N-SES-1).
                SyncDecisionResult answered = currentResult(event, userId, contextBindingHash, null);
                if (!result.analysed()) {
                    recordUnanalysed(event, answered.action());
                }
                return answered;
        }
    }

    private AgentDecisionFlights.Request flightRequest(ZeroTrustSpringEvent event, String userId,
                                                       String contextBindingHash) {
        Map<String, Object> payload = event.getPayload();
        return new AgentDecisionFlights.Request(decisionKey(event, userId), contextBindingHash,
                AgentAllowReuse.operation(payload, event.getResource()),
                AgentAllowReuse.resource(payload, event.getResource()),
                AgentAllowReuse.sensitive(payload), ResourceImportanceResolver.explicitlyNonSensitive(payload),
                synchronous(event));
    }

    /** Whether the protected method is synchronous, as the request's facts say. */
    private static boolean synchronous(ZeroTrustSpringEvent event) {
        Object sync = event.getPayload() != null ? event.getPayload().get("protectableSync") : null;
        return sync != null && Boolean.parseBoolean(sync.toString());
    }

    /** What the flights read of the stored state for one request. */
    private AgentDecisionFlights.Ground ground(ZeroTrustSpringEvent event, String userId, String contextBindingHash) {
        return new AgentDecisionFlights.Ground() {
            @Override
            public ZeroTrustAction restriction(AgentDecisionFlights.Request request) {
                ZeroTrustAction action = confirmed(event, currentAction(event, userId, contextBindingHash));
                return action == ZeroTrustAction.BLOCK || action == ZeroTrustAction.CHALLENGE
                        || action == ZeroTrustAction.ESCALATE ? action : null;
            }

            @Override
            public boolean covered(AgentDecisionFlights.Request request) {
                // A synchronous request is decided on its own whatever was allowed before (A7-2); an asynchronous
                // one is answered by the ALLOW in force as far as the anchor reaches (F-1).
                return !request.sync() && agentAllowReuse != null
                        && currentAction(event, userId, contextBindingHash) == ZeroTrustAction.ALLOW
                        && agentAllowReuse.answers(request.subjectKey(), contextBindingHash, request.operation(),
                        request.resource(), request.sensitive());
            }

            @Override
            public boolean coveredJoined(AgentDecisionFlights.Request request) {
                // The same, for a request that joined the flight whose ALLOW is in force: the request limit of the
                // anchor does not count it.
                return !request.sync() && agentAllowReuse != null
                        && currentAction(event, userId, contextBindingHash) == ZeroTrustAction.ALLOW
                        && agentAllowReuse.answersJoined(request.subjectKey(), contextBindingHash, request.operation(),
                        request.resource(), request.sensitive());
            }

            @Override
            public boolean decisionLanded(AgentDecisionFlights.Request request) {
                return currentAction(event, userId, contextBindingHash) != ZeroTrustAction.PENDING_ANALYSIS;
            }

            @Override
            public void allowed(AgentDecisionFlights.Request leader) {
                if (agentAllowReuse != null) {
                    agentAllowReuse.decided(leader.subjectKey(), leader.contextHash(), leader.operation(),
                            leader.resource(), leader.sensitive());
                }
            }
        };
    }

    public void setAgentDecisionFlights(AgentDecisionFlights agentDecisionFlights) {
        this.agentDecisionFlights = agentDecisionFlights;
    }

    /**
     * The restriction in force for the caller of an asynchronous {@code @Protectable}: a stored BLOCK, CHALLENGE or
     * ESCALATE restricts every request of the user, so it is checked before the method runs. Null when none is in
     * force or when the event is inside a shadow boundary. The restricted request does not run and reaches no
     * analysis; its session still keeps it (N-SES-1).
     */
    public ZeroTrustAction storedRestriction(MethodInvocation methodInvocation, Authentication authentication) {
        return asyncGate(methodInvocation, authentication).restriction();
    }

    /** Whether the protected call is for a sensitive resource, read as the gate of a call without a decision reads it. */
    public boolean sensitive(MethodInvocation methodInvocation, Authentication authentication) {
        return AgentAllowReuse.sensitive(zeroTrustEventPublisher.buildMethodAuthorizationEvent(
                methodInvocation, authentication, true, null).getPayload());
    }

    /**
     * What an asynchronous {@code @Protectable} does before it runs: the restriction in force ({@link
     * #storedRestriction}), or, A1-5, a decision in place for an agent request with no decision on record. An agent
     * is not let through without a decision (OWASP ASI02, ASI05); a person's request proceeds while it is analysed.
     * {@code contexa.security.zerotrust.protectable.unrecorded-agent-request=proceed} lets an agent's request proceed
     * while it is analysed as well.
     */
    public AsyncProtectableGate asyncGate(MethodInvocation methodInvocation, Authentication authentication) {
        ZeroTrustSpringEvent event = zeroTrustEventPublisher.buildMethodAuthorizationEvent(
                methodInvocation,
                authentication,
                true,
                null
        );
        if (isEventShadowBoundary(event)) {
            return AsyncProtectableGate.PROCEED;
        }
        String gateContext = zeroTrustEventListener.generateAuthorizationContextBindingHash(event);
        ZeroTrustAction action = confirmed(event, currentAction(event, event.getUserId(), gateContext));
        if (action != ZeroTrustAction.PENDING_ANALYSIS && flightsApply(event)) {
            // A verdict stands for the agent: the window in which requests passed before it is over.
            agentDecisionFlights.verdictSeen(decisionKey(event, event.getUserId()));
        }
        if (action == ZeroTrustAction.BLOCK || action == ZeroTrustAction.CHALLENGE
                || action == ZeroTrustAction.ESCALATE) {
            recordUnanalysed(event, action);
            return AsyncProtectableGate.restricted(action);
        }
        // docs/agent A7-3 (CF-25): a request its accountable person confirmed is read as allowed for that request
        // (AgentRequestConfirmation), so it is not decided again in place; the analysis after it still runs.
        if (action == ZeroTrustAction.PENDING_ANALYSIS
                && unrecordedAgentRequest == SecurityZeroTrustProperties.UnrecordedAgentRequest.DECIDE_IN_PLACE
                && agentRequest(event) && AgentRequestConfirmation.current() == null) {
            if (flightsApply(event)) {
                // docs/agent RL-12: a few reads of a resource the host declared non-sensitive pass while the first
                // is decided in the background; the first begins that decision, the others are only recorded.
                AgentDecisionFlights.Pass pass = agentDecisionFlights.tryPass(
                        flightRequest(event, event.getUserId(), gateContext),
                        ground(event, event.getUserId(), gateContext));
                if (pass == AgentDecisionFlights.Pass.LEAD) {
                    return AsyncProtectableGate.PASS_AND_ANALYSE;
                }
                if (pass == AgentDecisionFlights.Pass.FOLLOW) {
                    recordPassed(event);
                    return AsyncProtectableGate.PASS_AND_RECORD;
                }
            }
            return AsyncProtectableGate.DECIDE_IN_PLACE;
        }
        // docs/agent F-1: an ALLOW answers an agent's later requests only for the same operation and a few resources;
        // past them the request is decided here, before it runs.
        if (action == ZeroTrustAction.ALLOW && agentAllowReuse != null && agentRequest(event)
                && AgentRequestConfirmation.current() == null
                && !agentAllowReuse.answers(decisionKey(event, event.getUserId()),
                zeroTrustEventListener.generateAuthorizationContextBindingHash(event),
                AgentAllowReuse.operation(event.getPayload(), event.getResource()),
                AgentAllowReuse.resource(event.getPayload(), event.getResource()),
                AgentAllowReuse.sensitive(event.getPayload()))) {
            return AsyncProtectableGate.DECIDE_IN_PLACE;
        }
        if (action == ZeroTrustAction.PENDING_ANALYSIS && !agentRequest(event) && enforcing.getAsBoolean()) {
            if (personRequest(event) && contextChanged(event, gateContext)) {
                if (pastTheChangedContextLimit(event, gateContext)) {
                    return pastTheLimit(event, gateContext);
                }
                if (AgentAllowReuse.sensitive(event.getPayload())) {
                    throw sensitiveWaitsForItsContext(methodInvocation, authentication, event, gateContext);
                }
            }
            if (AgentAllowReuse.sensitive(event.getPayload()) && securityPlaneAgent.isBehind()) {
                return heldForItsVerdict(methodInvocation, authentication, event, gateContext);
            }
        }
        return AsyncProtectableGate.PROCEED;
    }

    /**
     * Whether the request comes from another context than the user's decision was reached for: another session, address
     * or browser. With nothing on record there is nothing to compare, so no change. A record that cannot be read tells
     * neither: a general resource goes on as a store outage lets it, and a sensitive one is taken for a change, as it
     * does not go without a decision.
     */
    private boolean contextChanged(ZeroTrustSpringEvent event, String gateContext) {
        try {
            String decided = actionRepository.decidedContext(decisionKey(event, event.getUserId()));
            return decided != null && gateContext != null && !decided.equals(gateContext);
        } catch (RuntimeException unreadable) {
            if (!StoreFailures.isReportedOutage(unreadable)) {
                log.error("[ZeroTrust] The context of the user's decision could not be read: userId={}",
                        event.getUserId(), unreadable);
            }
            return AgentAllowReuse.sensitive(event.getPayload());
        }
    }

    /**
     * The answer to a request for a sensitive resource from a changed context that no decision stands for yet: it is not let
     * out before a verdict, and no thread waits for it. A stolen session used from elsewhere is this request, and a
     * verdict that comes after the response comes after its data (a response cut stops a stream that is still running,
     * and not a record that was sent whole). The request is turned away with "come back in a few seconds" (503 and
     * {@code Retry-After}); the analysis of its context is started once, as it would be for a request that goes on, and the
     * call after the verdict is answered by it: ALLOW lets it through, a BLOCK or a CHALLENGE stops it. A resource the host
     * did not declare sensitive is not held, and neither is a user with nothing on record, who has nothing to compare with.
     */
    private ZeroTrustAccessDeniedException sensitiveWaitsForItsContext(MethodInvocation methodInvocation,
                                                                       Authentication authentication,
                                                                       ZeroTrustSpringEvent event, String gateContext) {
        String question = decisionKey(event, event.getUserId()) + '\u0000' + gateContext;
        if (contextsAskedAbout.putIfAbsent(question, Boolean.TRUE)) {
            zeroTrustEventPublisher.publishMethodAuthorization(methodInvocation, authentication, true, null,
                    ZeroTrustEventPublisher.METHOD_NOT_RUN, null);
        }
        return ZeroTrustAccessDeniedException.analysisBusy(event.getResource(), CHANGED_CONTEXT_RETRY_AFTER_SECONDS);
    }

    /**
     * Whether the request is past the decisions of a new context a person may ask for in the window. A call from a changed
     * context goes on while it is analysed and does not wait for the verdict, but each such context is a decision of the
     * model that someone pays for, and whoever holds a person's session can change the browser string at every call. The
     * first call of a context takes one place from the limit and the others of the same context take none, and a context
     * that found no place stays refused for as long as it is remembered. The answer is the CHALLENGE of {@link
     * #pastTheLimit}, for that call alone. With no limit set nothing is past it.
     */
    private boolean pastTheChangedContextLimit(ZeroTrustSpringEvent event, String gateContext) {
        if (newContextDecisionLimit == null) {
            return false;
        }
        String subject = decisionKey(event, event.getUserId());
        Boolean granted = contextsOfTheLimit.atomically(subject + '\u0000' + gateContext, slot -> {
            if (slot.value() != null) {
                return slot.value();
            }
            boolean taken = newContextDecisionLimit.take(subject, NewContextDecisionLimit.Kind.CHANGED_CONTEXT);
            slot.set(taken);
            return taken;
        });
        return !Boolean.TRUE.equals(granted);
    }

    /**
     * The answer to a person's request from a changed context, which comes after its verdict: a stolen session used from
     * elsewhere is this request, and a verdict after the response would come after its data. The requests of one context
     * ask the model once: the first analyses, on the wait of a synchronous request, and the others wait for its end and
     * are answered by what it left in force. So a page's calls at once after a change of network all run on one verdict,
     * and none is refused because another is being analysed. On several servers each asks for itself.
     */
    private AsyncProtectableGate answerToAChangedContext(ZeroTrustSpringEvent event, String gateContext) {
        String question = decisionKey(event, event.getUserId()) + '\u0000' + gateContext;
        if (unansweredContexts.containsKey(question)) {
            return withoutItsVerdict(event, gateContext);
        }
        VerdictUnderWay mine = new VerdictUnderWay();
        VerdictUnderWay underWay = changedContextVerdicts.putIfAbsent(question, mine);
        if (underWay != null) {
            return answerAfter(underWay, event, gateContext);
        }
        try {
            return answerOfItsVerdict(event, gateContext, question, mine);
        } finally {
            changedContextVerdicts.remove(question, mine);
            mine.end.complete(null);
        }
    }

    /**
     * The answer to a request that waits for the verdict another request asked for. The waiting room holds as many as the
     * flights' queue: the requests of one context must not take the application's threads while a model is slow. A request
     * past it is told to come back, and is never let through for lack of room. A request whose context the decision limit
     * refused is refused with it: it is the same question, and letting it through would pass the limit.
     */
    private AsyncProtectableGate answerAfter(VerdictUnderWay underWay, ZeroTrustSpringEvent event, String gateContext) {
        int room = (agentDecisionFlights != null ? agentDecisionFlights.settings()
                : AgentDecisionFlights.Settings.defaults()).queueCapacity();
        if (underWay.waiting.incrementAndGet() > room) {
            underWay.waiting.decrementAndGet();
            throw ZeroTrustAccessDeniedException.analysisBusy(event.getResource(), WAITING_ROOM_RETRY_AFTER_SECONDS);
        }
        try {
            awaitTheEnd(underWay.end);
        } finally {
            underWay.waiting.decrementAndGet();
        }
        if (underWay.pastTheLimit) {
            return pastTheLimit(event, gateContext);
        }
        return answerInForce(event, gateContext);
    }

    /**
     * The verdict of the request that asks. A decision that landed since the gate read the store answers it, and one
     * that waits for its audit record is not asked for again. Its event is the analysis, so nothing is published after
     * the method: a request let through is only recorded.
     */
    private AsyncProtectableGate answerOfItsVerdict(ZeroTrustSpringEvent event, String gateContext, String question,
                                                    VerdictUnderWay mine) {
        if (!zeroTrustEventListener.shouldPublishAuthorizationEvent(event)) {
            return answerInForce(event, gateContext);
        }
        if (newContextDecisionLimit != null && !newContextDecisionLimit.take(decisionKey(event, event.getUserId()),
                NewContextDecisionLimit.Kind.CHANGED_CONTEXT)) {
            mine.pastTheLimit = true;
            return pastTheLimit(event, gateContext);
        }
        ZeroTrustAction verdict = null;
        try {
            verdict = verdictOf(event, event.getUserId(), gateContext).action();
        } catch (DecisionNotInTimeException notInTime) {
            log.debug("[ZeroTrust] No verdict in time for a changed context: userId={}", event.getUserId());
            unansweredContexts.put(question, Boolean.TRUE);
        } catch (RuntimeException failure) {
            // Neither a model nor a store that fails is the application's failure: what is in force answers.
            if (!StoreFailures.isStoreFailure(failure)) {
                log.error("[ZeroTrust] The analysis of a changed context failed: userId={}", event.getUserId(), failure);
            }
        }
        if (verdict == ZeroTrustAction.ALLOW) {
            return AsyncProtectableGate.PASS_AND_RECORD;
        }
        if (verdict != null && verdict.isAccessRestricted()) {
            return AsyncProtectableGate.restricted(verdict);
        }
        return withoutItsVerdict(event, gateContext);
    }

    /**
     * The answer to a call from a changed context past the person's decisions of a new context in the window: the model
     * is not asked, and the call is refused with a CHALLENGE of its own, for a general resource too, since a context
     * that keeps changing is the signal itself. Nothing is stored: the calls of the context on record go on as they did,
     * and the window's next room decides this context. A stricter decision in force answers it as it would. While a
     * store is down the call is asked to come back instead, as no verification could be kept.
     */
    private AsyncProtectableGate pastTheLimit(ZeroTrustSpringEvent event, String gateContext) {
        ZeroTrustAction inForce = currentAction(event, event.getUserId(), gateContext);
        if (inForce != null && inForce.isAccessRestricted()) {
            recordUnanalysed(event, inForce);
            return AsyncProtectableGate.restricted(inForce);
        }
        if (contexaStores.anyDown()) {
            throw ZeroTrustAccessDeniedException.analysisBusy(event.getResource(), STORE_RETRY_AFTER_SECONDS);
        }
        recordUnanalysed(event, ZeroTrustAction.CHALLENGE);
        return AsyncProtectableGate.restricted(ZeroTrustAction.CHALLENGE);
    }

    /** The answer of a request whose analysis ran or was not asked for: nothing is published after the method. */
    private AsyncProtectableGate withoutItsVerdict(ZeroTrustSpringEvent event, String gateContext) {
        AsyncProtectableGate answer = answerInForce(event, gateContext);
        return answer == AsyncProtectableGate.PROCEED ? AsyncProtectableGate.PASS_AND_RECORD : answer;
    }

    /** The end of the analysis a request waits for, within a synchronous request's wait. */
    private void awaitTheEnd(Future<Void> analysis) {
        try {
            if (decisionWait != null) {
                verdictInTime(analysis, decisionWait);
            } else {
                analysis.get();
            }
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        } catch (ExecutionException | DecisionNotInTimeException notEnded) {
            log.debug("[ZeroTrust] The analysis of a changed context did not end in time");
        }
    }

    /**
     * What answers a request of a changed context from what is in force. Without a verdict a general resource goes on,
     * as it does while the analysis is behind and while a store is down: stopping it would turn a slow model into a
     * stopped application. A sensitive resource does not go on: the refusal is this request's and nothing is stored. It
     * is asked to verify, or to come back while a store is down, when no verification could be kept.
     */
    private AsyncProtectableGate answerInForce(ZeroTrustSpringEvent event, String gateContext) {
        ZeroTrustAction inForce = currentAction(event, event.getUserId(), gateContext);
        if (inForce == ZeroTrustAction.ALLOW) {
            return AsyncProtectableGate.PROCEED;
        }
        if (inForce != null && inForce.isAccessRestricted()) {
            recordUnanalysed(event, inForce);
            return AsyncProtectableGate.restricted(inForce);
        }
        if (!AgentAllowReuse.sensitive(event.getPayload())) {
            recordPassed(event);
            return AsyncProtectableGate.PASS_AND_RECORD;
        }
        if (contexaStores.anyDown()) {
            throw ZeroTrustAccessDeniedException.analysisBusy(event.getResource(), STORE_RETRY_AFTER_SECONDS);
        }
        return AsyncProtectableGate.restricted(ZeroTrustAction.CHALLENGE);
    }

    /**
     * Q-23: while the analysis is behind, a request to a sensitive resource does not go without a decision, or filling
     * the line would be a way past it. Its analysis is asked for first, among the first decisions; it waits a moment
     * for the verdict and is then refused. The refusal is this request's: nothing is stored, the user's other requests
     * go on, and the verdict that comes answers the next one. A general resource passes as it does while the engine
     * keeps up, and stopping every request would turn a slow model into a stopped application.
     */
    private AsyncProtectableGate heldForItsVerdict(MethodInvocation methodInvocation, Authentication authentication,
                                                   ZeroTrustSpringEvent event, String gateContext) {
        zeroTrustEventPublisher.publishMethodAuthorization(methodInvocation, authentication, true, null,
                ZeroTrustEventPublisher.METHOD_NOT_RUN, null);
        ZeroTrustAction verdict = awaitVerdict(event, gateContext);
        if (verdict == ZeroTrustAction.ALLOW) {
            return AsyncProtectableGate.PASS_AND_RECORD;
        }
        return AsyncProtectableGate.restricted(verdict == ZeroTrustAction.PENDING_ANALYSIS
                ? ZeroTrustAction.CHALLENGE : verdict);
    }

    private ZeroTrustAction awaitVerdict(ZeroTrustSpringEvent event, String gateContext) {
        long until = System.nanoTime() + behindWait.toNanos();
        while (true) {
            ZeroTrustAction action = currentAction(event, event.getUserId(), gateContext);
            if (action != ZeroTrustAction.PENDING_ANALYSIS) {
                return action;
            }
            long left = until - System.nanoTime();
            if (left <= 0L) {
                return ZeroTrustAction.PENDING_ANALYSIS;
            }
            try {
                TimeUnit.MILLISECONDS.sleep(Math.min(VERDICT_POLL_MS, TimeUnit.NANOSECONDS.toMillis(left) + 1L));
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                return ZeroTrustAction.PENDING_ANALYSIS;
            }
        }
    }

    /** docs/agent F-1: how far an ALLOW in force answers an agent's later requests. */
    public void setAgentAllowReuse(AgentAllowReuse agentAllowReuse) {
        this.agentAllowReuse = agentAllowReuse;
    }

    /** docs/agent F-1: an agent's request decided here; its ALLOW answers the requests like it. */
    private void agentDecided(ZeroTrustSpringEvent event, String contextBindingHash) {
        if (agentAllowReuse != null && agentRequest(event)) {
            agentAllowReuse.decided(decisionKey(event, event.getUserId()), contextBindingHash,
                    AgentAllowReuse.operation(event.getPayload(), event.getResource()),
                    AgentAllowReuse.resource(event.getPayload(), event.getResource()),
                    AgentAllowReuse.sensitive(event.getPayload()));
        }
        if (agentDecisionFlights != null && agentRequest(event)) {
            agentDecisionFlights.verdictSeen(decisionKey(event, event.getUserId()));
        }
    }

    /** A request that passed before the verdict is a fact of its session; it is not learned. */
    private void recordPassed(ZeroTrustSpringEvent event) {
        if (unanalysedRequestRecorder != null) {
            unanalysedRequestRecorder.recordPassed(event);
        }
    }

    public void setUnrecordedAgentRequest(SecurityZeroTrustProperties.UnrecordedAgentRequest unrecordedAgentRequest) {
        this.unrecordedAgentRequest = unrecordedAgentRequest != null
                ? unrecordedAgentRequest
                : SecurityZeroTrustProperties.UnrecordedAgentRequest.DECIDE_IN_PLACE;
    }

    /** Whether a person makes the request: neither an agent nor a client acting with its own token. */
    private static boolean personRequest(ZeroTrustSpringEvent event) {
        ZeroTrustSubject subject = ZeroTrustSubject.ofFacts(event.getUserId(), event.getPayload());
        return subject != null && (subject.kind() == SubjectKind.HUMAN_USER || subject.console());
    }

    /** The subject the publisher recorded on the event (A1-3). */
    private static boolean agentRequest(ZeroTrustSpringEvent event) {
        if (event == null || event.getPayload() == null) {
            return false;
        }
        Object kind = event.getPayload().get("executionSubjectKind");
        if (kind == null) {
            return false;
        }
        try {
            return SubjectKind.valueOf(kind.toString().trim()).agent();
        } catch (IllegalArgumentException unknownKind) {
            return false;
        }
    }

    private void recordUnanalysed(ZeroTrustSpringEvent event, ZeroTrustAction action) {
        if (unanalysedRequestRecorder != null) {
            unanalysedRequestRecorder.record(event, action);
        }
    }

    private SyncDecisionResult currentResult(
            ZeroTrustSpringEvent event,
            String userId,
            String contextBindingHash,
            SecurityEventContext processingContext) {
        return new SyncDecisionResult(
                event,
                contextBindingHash,
                resolveSynchronousAction(event, userId, contextBindingHash, processingContext),
                actionRepository.getAnalysisData(decisionKey(event, userId)),
                processingContext
        );
    }

    /**
     * What the request is answered with. Decisions come out for one user at once, each from its own analysis, and the
     * store keeps the strictest (RL-13), so a request's own decision is not its answer until the store was looked at:
     * a restriction in force answers it, as the flights' final gate does for an agent, whichever session it was decided
     * for (PR-86). What is not stricter than the request's own decision changes nothing.
     */
    private ZeroTrustAction resolveSynchronousAction(
            ZeroTrustSpringEvent event,
            String userId,
            String contextBindingHash,
            SecurityEventContext processingContext) {
        ProcessingResult processingResult = processingResult(processingContext);
        if (processingResult != null && isEventShadowBoundary(event)) {
            return ZeroTrustAction.ALLOW;
        }
        ZeroTrustAction stored = currentAction(event, userId, contextBindingHash);
        ZeroTrustAction processingAction = processingAction(processingResult);
        if (processingAction == null) {
            return confirmed(event, stored);
        }
        ZeroTrustAction decided = confirmed(event, processingAction);
        if (decided == ZeroTrustAction.ALLOW && keptOutByStricterAction(processingContext)
                && (stored == null || !stored.isAccessRestricted())) {
            // The write said a stricter action stays, and the store shows none: it cannot be read, or it ended this
            // moment. Either way this ALLOW did not take effect, so it lets nothing through (PR-86).
            return ZeroTrustAction.PENDING_ANALYSIS;
        }
        ZeroTrustAction inForce = confirmed(event, stored);
        return ZeroTrustActionPrecedence.keepsActiveRestriction(inForce, decided) ? inForce : decided;
    }

    /** Whether the enforcement left this decision out because a stricter action stayed in effect (W5-3). */
    private static boolean keptOutByStricterAction(SecurityEventContext processingContext) {
        SecurityEvent decided = processingContext.getSecurityEvent();
        return decided != null && decided.getMetadata() != null
                && AgentDecisionRecord.KEPT_STRICTER.equals(decided.getMetadata().get(AgentDecisionRecord.ENFORCEMENT_OUTCOME));
    }

    /**
     * docs/agent A5-2: an agent's request the accountable person confirmed answers a CHALLENGE, for that request only;
     * a BLOCK or an ESCALATE stays.
     */
    private static ZeroTrustAction confirmed(ZeroTrustSpringEvent event, ZeroTrustAction action) {
        return action == ZeroTrustAction.CHALLENGE && agentRequest(event) && AgentRequestConfirmation.current() != null
                ? ZeroTrustAction.ALLOW : action;
    }

    /**
     * docs/agent A5-1: the decision in force for the request's subject; an agent acting for the user reads its own
     * decision (and the user's BLOCK), everyone else the user's.
     */
    private ZeroTrustAction currentAction(ZeroTrustSpringEvent event, String userId, String contextBindingHash) {
        ZeroTrustSubject subject = ZeroTrustSubject.ofFacts(userId, event.getPayload());
        return subject != null ? subject.currentAction(actionRepository, contextBindingHash)
                : actionRepository.getCurrentAction(userId, contextBindingHash);
    }

    private static String decisionKey(ZeroTrustSpringEvent event, String userId) {
        ZeroTrustSubject subject = ZeroTrustSubject.ofFacts(userId, event.getPayload());
        return subject != null ? subject.storageKey() : userId;
    }

    private ProcessingResult processingResult(SecurityEventContext processingContext) {
        if (processingContext == null || processingContext.getMetadata() == null) {
            return null;
        }
        Object result = processingContext.getMetadata().get("processingResult");
        return result instanceof ProcessingResult processingResult ? processingResult : null;
    }

    private ZeroTrustAction processingAction(ProcessingResult processingResult) {
        if (processingResult == null) {
            return null;
        }
        // The final action includes autonomy constraints and technical fallbacks and is
        // therefore the action that synchronous enforcement must apply. proposedAction
        // is retained for audit purposes only.
        if (StringUtils.hasText(processingResult.getAction())) {
            return ZeroTrustAction.fromString(processingResult.getAction());
        }
        if (StringUtils.hasText(processingResult.getProposedAction())) {
            return ZeroTrustAction.fromString(processingResult.getProposedAction());
        }
        return null;
    }

    private boolean isEventShadowBoundary(ZeroTrustSpringEvent event) {
        if (event == null || event.getPayload() == null) {
            return false;
        }
        return "SHADOW".equalsIgnoreCase(firstText(event.getPayload().get("decisionBoundaryMode")));
    }

    private String firstText(Object... values) {
        if (values == null) {
            return null;
        }
        for (Object value : values) {
            if (value == null) {
                continue;
            }
            String text = value.toString().trim();
            if (StringUtils.hasText(text)) {
                return text;
            }
        }
        return null;
    }

    /**
     * The restriction in force, or whether the request is decided in place, or whether it passes before its verdict
     * (RL-12) and whether its event is then analysed; none of these means it proceeds.
     */
    public record AsyncProtectableGate(ZeroTrustAction restriction, boolean decideInPlace, boolean passed,
                                       boolean publishesEvent) {

        public static final AsyncProtectableGate PROCEED = new AsyncProtectableGate(null, false, false, true);
        public static final AsyncProtectableGate DECIDE_IN_PLACE = new AsyncProtectableGate(null, true, false, false);
        /** It passes; its event is analysed in the background, and that analysis is the verdict the others wait for. */
        public static final AsyncProtectableGate PASS_AND_ANALYSE = new AsyncProtectableGate(null, false, true, true);
        /** It passes and is only recorded: a verdict is in, or already pending. */
        public static final AsyncProtectableGate PASS_AND_RECORD = new AsyncProtectableGate(null, false, true, false);

        public static AsyncProtectableGate restricted(ZeroTrustAction restriction) {
            return new AsyncProtectableGate(restriction, false, false, false);
        }
    }

    /** The verdict one request asked for, the end of its analysis and the requests waiting for it. */
    private static final class VerdictUnderWay {
        private final CompletableFuture<Void> end = new CompletableFuture<>();
        private final AtomicInteger waiting = new AtomicInteger();
        /** Set before the end: the decision limit refused the question, so its waiting requests are refused too. */
        private volatile boolean pastTheLimit;
    }

    /** The verdict of a synchronous request did not come in time. */
    private static final class DecisionNotInTimeException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        private DecisionNotInTimeException() {
            super(null, null, false, false);
        }
    }

    public record SyncDecisionResult(
            ZeroTrustSpringEvent event,
            String contextBindingHash,
            ZeroTrustAction action,
            ZeroTrustActionRepository.ZeroTrustAnalysisData analysisData,
            SecurityEventContext processingContext
    ) {
    }
}
