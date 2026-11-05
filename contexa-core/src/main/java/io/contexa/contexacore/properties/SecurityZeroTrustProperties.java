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
package io.contexa.contexacore.properties;

import io.contexa.contexacore.autonomous.context.decision.LearningPromotionPolicy;
import io.contexa.contexacore.autonomous.context.decision.MinimumActionRules;
import io.contexa.contexacore.autonomous.execution.ObjectiveResourceCompatibilityCatalog;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Data
@ConfigurationProperties(prefix = "contexa.security.zerotrust")
public class SecurityZeroTrustProperties {

    /** Whether a signed-in user's responses carry X-Contexa-Monitored and X-Contexa-Blocked-Redirect, which Contexa's browser SDK reads. */
    private boolean monitoringHeaders = true;

    private boolean enabled = true;

    private EnforcementMode mode = EnforcementMode.ENFORCE;

    private int maxBlockMfaAttempts = 2;

    public enum EnforcementMode {
        DISABLED,
        OBSERVE,
        SHADOW,
        ENFORCE;

        public boolean allowsLlmAnalysis() {
            return this == SHADOW || this == ENFORCE;
        }

        public boolean isEnforcementEnabled() {
            return this == ENFORCE;
        }
    }

    public boolean allowsLlmAnalysis() {
        return enabled && mode != null && mode.allowsLlmAnalysis();
    }

    public boolean isEnforcementEnabled() {
        return enabled && mode != null && mode.isEnforcementEnabled();
    }

    @NestedConfigurationProperty
    private SamplingSettings sampling = new SamplingSettings();

    @NestedConfigurationProperty
    private HotPathSettings hotpath = new HotPathSettings();

    @NestedConfigurationProperty
    private ThresholdsSettings thresholds = new ThresholdsSettings();

    @NestedConfigurationProperty
    private ProtectableSettings protectable = new ProtectableSettings();

    @NestedConfigurationProperty
    private AgentSettings agent = new AgentSettings();

    /** docs/agent A5-8: the revocation and risk signals Contexa receives. */
    private RiskSignals riskSignals = new RiskSignals();

    /** docs/agent B4: the OpenID AuthZEN evaluation API other enforcement points ask Contexa's decision through. */
    private Authzen authzen = new Authzen();

    @NestedConfigurationProperty
    private RedisSettings redis = new RedisSettings();

    @NestedConfigurationProperty
    private ThreatSettings threat = new ThreatSettings();

    @NestedConfigurationProperty
    private CacheSettings cache = new CacheSettings();

    @NestedConfigurationProperty
    private SessionSettings session = new SessionSettings();

    @NestedConfigurationProperty
    private SessionTrackingSettings sessionTracking = new SessionTrackingSettings();

    @NestedConfigurationProperty
    private ChallengeSettings challenge = new ChallengeSettings();

    @NestedConfigurationProperty
    private AnalysisSettings analysis = new AnalysisSettings();

    @NestedConfigurationProperty
    private BaselineSettings baseline = new BaselineSettings();

    /** The minimum-action rules of the security decision (plan 7, dictionary 6, W4-4). */
    @NestedConfigurationProperty
    private MinimumActionSettings minimumAction = new MinimumActionSettings();

    /** QF-42: the bounds of the stores of the standalone mode, which keep decisions and learning in memory. */
    @NestedConfigurationProperty
    private StandaloneSettings standalone = new StandaloneSettings();

    @Data
    public static class ThreatSettings {
        private double initial = 0.3;
    }

    @Data
    public static class CacheSettings {
        private int ttlHours = 24;
        private int sessionTtlMinutes = 30;
        private int invalidatedTtlMinutes = 60;
    }

    @Data
    public static class SessionSettings {
        private boolean trackingEnabled = true;
    }

    /** The session ids kept per user so a forced logout reaches every live session of the user. */
    @Data
    public static class SessionTrackingSettings {

        public static final int DEFAULT_MAX_UNTIMED_SESSIONS_PER_USER = 64;

        /**
         * QF-57: an id is tracked until it is certainly dead: an OAuth2 token's until the token expires, an HTTP
         * session's until its idle limit has passed since its last request. This is the most ids per user kept among
         * those nothing on the request bounds the life of (an identity the host asserts without an HTTP session or a
         * token, a session that never times out); past it the least recently seen are no longer tracked, so a forced
         * logout does not reach them until their next request registers them again. 0 or less keeps them all.
         */
        private int maxUntimedSessionsPerUser = DEFAULT_MAX_UNTIMED_SESSIONS_PER_USER;
    }

    @Data
    public static class ChallengeSettings {
        private Duration lockWaitTime = Duration.ZERO;
        private Duration lockLeaseTime = Duration.ofSeconds(30);
        private int busyRetryAfterSeconds = 3;
    }

    @Data
    public static class StandaloneSettings {
        /**
         * QF-42: the most users the in-memory decision store keeps; past it the users whose decision was written the
         * longest ago go first, never one whose state restricts (BLOCK, a CHALLENGE or ESCALATE in force, a pending
         * BLOCK MFA, a decision audit marker) nor one decided within the decision's TTL. 0 or less derives it from the
         * maximum heap: a twentieth of it at 2 KiB a user, between 1,000 and 1,000,000 (52,428 users for a 2 GiB heap).
         */
        private int maxDecisionUsers = 0;

        /**
         * QF-42: the bytes the requests held for verification and promotion learning may take together in the
         * in-memory context store, counted at two bytes a character of their records; past it the requests held the
         * longest ago are released, whoever holds them, so their later verification or promotion is not learned (no
         * decision changes). 0 or less derives it from the maximum heap: a tenth of it, between 16 MiB and 1 GiB
         * (204.8 MiB for a 2 GiB heap). The Redis store is not bounded by it.
         */
        private long maxHeldLearningBytes = 0;
    }

    @Data
    public static class AnalysisSettings {
        private long maxAgeMs = 3_600_000L;

        /**
         * How long new analysis for an actor context is suspended after its final decision
         * could not be written to the decision observation store.
         */
        private long auditFailureCooldownMs = 30_000L;
    }

    @Data
    public static class BaselineSettings {
        /**
         * BR-C11 (DD-52): how long a stored baseline, personal or organization, is kept after its last learning; each
         * learning keeps it for this long again. A baseline not learned for this long is removed whole.
         */
        private Duration retention = Duration.ofDays(30);

        @NestedConfigurationProperty
        private LearningSettings learning = new LearningSettings();

        @NestedConfigurationProperty
        private StatisticalSettings statistical = new StatisticalSettings();

        @NestedConfigurationProperty
        private PromotionSettings promotion = new PromotionSettings();

        @Data
        public static class LearningSettings {
            private boolean enabled = true;
            private double alpha = 0.1;
            /**
             * The weight of a request learned after the user passed the step-up its decision asked for, or after an
             * administrator released its block, against an allowed request's 1 (W5-2).
             */
            private double verifiedWeight = 0.5;
            /**
             * docs/agent A3-4: how long a value learned without a verification stays in the stored baseline when it is
             * not seen again; the default is the usual comparison's fallback window.
             */
            private Duration unverifiedExpiry = Duration.ofDays(30);
            /**
             * docs/agent A3-4: the half-life by which a learned value's frequency counts less with its age when the
             * values of a dimension compete for its places; the default is the usual comparison's half-life.
             */
            private Duration halfLife = Duration.ofDays(14);
        }

        /**
         * When a personal baseline is established (W5-10 D4): enough learned requests, learned on enough company
         * dates, and its recent learnings no longer bringing values it had not seen.
         */
        @Data
        public static class StatisticalSettings {
            private int minSamples = 20;
            private int minDays = 5;
            private int convergenceWindow = 10;
            private double maxNewValueRatio = 0.2;
            /**
             * QF-21: how many different members an organization baseline's learned requests must come from, on at least
             * {@code minDays} company dates, before it is established.
             */
            private int minOrganizationMembers = 3;
        }

        /**
         * The learning promotion (W5-1, plan L1): an allowed request on a resource of at least the minimum class
         * whose time, day, network or device differs from the usual behaviour with nothing to explain it is held
         * back, and learned once the same value is held on the given number of different days, or once the user
         * passes a verification on a request with that value.
         */
        @Data
        public static class PromotionSettings {
            private boolean enabled = true;
            private String minResourceClass = "SENSITIVE";
            private int minObservations = 2;
            private int minDistinctDays = 2;
            private boolean verifiedPromotes = true;
            /** docs/agent A3-7: the agent rule: an agent's first values held back at any resource class. */
            @NestedConfigurationProperty
            private AgentPromotionSettings agent = new AgentPromotionSettings();

            /** The policy settings these keys give (contexa.security.zerotrust.baseline.promotion.*). */
            public LearningPromotionPolicy.Settings toPolicy() {
                return new LearningPromotionPolicy.Settings(enabled, minResourceClass, minObservations,
                        minDistinctDays, verifiedPromotes, agent == null || agent.isEnabled());
            }
        }

        /**
         * docs/agent A3-7: whether an agent's request holds back its first target, action, size, rate, network and
         * device at any resource class until they are seen on enough days or verified.
         */
        @Data
        public static class AgentPromotionSettings {
            private boolean enabled = true;
        }
    }

    @Data
    public static class SamplingSettings {
        private double rate = 1.0;
    }

    @Data
    public static class HotPathSettings {
        private boolean enabled = true;
    }

    @Data
    public static class ThresholdsSettings {
        private double skip = 0.3;
        private double optional = 0.5;
        private double required = 0.7;
        private double strict = 0.9;
    }

    @Data
    public static class ProtectableSettings {
        private long rapidReentryWindowMs = 5000;
        /**
         * How an agent's request to an asynchronous {@code @Protectable} method with no decision on record is handled.
         * By default it is decided in the request, so an agent is not let through without a decision (OWASP ASI02,
         * ASI05); a person's request keeps proceeding while it is analysed.
         */
        private UnrecordedAgentRequest unrecordedAgentRequest = UnrecordedAgentRequest.DECIDE_IN_PLACE;
    }

    @Data
    public static class AgentSettings {
        /**
         * How often the same agent's requests are written to the agent registry; requests in between only reach the
         * decision. The first request of an agent is always written.
         */
        private Duration registryWriteInterval = Duration.ofMinutes(1);

        /**
         * docs/agent OC-1: the longest a delegation recorded through Contexa's delegation API may last; a longer one is
         * refused. A delegation is given again when its work goes on.
         */
        private Duration delegationMaxValidity = Duration.ofDays(30);

        /**
         * docs/agent OC-3: how long an access token of an agent registered through Contexa's agent registration lives,
         * unless the registration names another lifetime.
         */
        private Duration clientTokenLifetime = Duration.ofMinutes(30);

        /**
         * docs/agent A5-2: how long a request of an agent waits for the accountable person's confirmation before it is
         * refused, and how long an approval may then be used by the request it is bound to.
         */
        private Duration confirmationTimeout = Duration.ofMinutes(15);

        /** docs/agent A5-2: how often the confirmations whose time ran out are refused and recorded. */
        private Duration confirmationSweepInterval = Duration.ofMinutes(1);

        /**
         * docs/agent A5-2: the absolute address the confirmation link in a notice starts with (for example
         * {@code https://app.example.com}); empty takes the address of the agent's request.
         */
        private String confirmationLinkBaseUrl;

        /**
         * docs/agent A5-9: the largest request body a confirmation is bound to; a larger request that needs a
         * confirmation is refused.
         */
        private int confirmationMaxBodyBytes = 1024 * 1024;

        /** docs/agent A5-4: how a decision narrows an agent's later requests. */
        private ScopeNarrowing scopeNarrowing = new ScopeNarrowing();

        /** docs/agent A5-7: the call limits of agents and delegations, and what passing them does. */
        private CallLimit callLimit = new CallLimit();

        /** docs/agent A5-7: the alarm on an agent whose requests are refused unusually often. */
        private DenialAlarm denialAlarm = new DenialAlarm();

        /** docs/agent F-1: how far an ALLOW in force answers an agent's later requests without a new decision. */
        private AllowReuse allowReuse = new AllowReuse();

        /**
         * docs/agent RL-12: what the engine does when one agent's requests come in numbers: the same question is
         * analysed once, the analyses one agent has running at once are limited, and a restriction stored while requests
         * wait answers them. Off by default.
         */
        private Flight flight = new Flight();

        /**
         * The business objectives the application declares, by objective family (the family a delegation record or
         * token names). A delegation of one of these objectives is compared with its contract; Contexa's own security
         * objectives stay known. Empty by default.
         */
        private Map<String, ObjectiveContract> objectiveContracts = new LinkedHashMap<>();

        /** The declared contracts in the catalog's form. */
        public List<ObjectiveResourceCompatibilityCatalog.ObjectiveContractDefinition> objectiveContractDefinitions() {
            List<ObjectiveResourceCompatibilityCatalog.ObjectiveContractDefinition> definitions = new ArrayList<>();
            objectiveContracts.forEach((family, contract) -> definitions.add(
                    new ObjectiveResourceCompatibilityCatalog.ObjectiveContractDefinition(family,
                            contract.getOperations(), contract.getResourceFamilies(), contract.isReadOnly(),
                            contract.isPrivilegedExportAllowed(), contract.getMaxExportItems())));
            return definitions;
        }
    }

    /**
     * docs/agent A5-4: the default narrowing. After a CHALLENGE, ESCALATE or BLOCK on an agent's request, or an ALLOW
     * whose risk reaches {@code riskThreshold}, the agent's later requests only read for {@code duration}.
     */
    /**
     * docs/agent RL-12. Requests that the engine cannot take in within {@code queueCapacity} and {@code wait} are
     * refused with HTTP 429; no request is let through for lack of a verdict, except the few reads of a resource the host
     * declared non-sensitive that {@code passBudget} allows while the first one is being decided.
     */
    @Data
    public static class Flight {
        /** Off, every agent request that no stored decision answers is analysed on its own, as before. */
        private boolean enabled = false;
        /** The analyses one agent may have running at once, whatever the contexts it works in. */
        private int maxInFlightAnalyses = 3;
        /** The requests of one agent that may wait for a place to be analysed. */
        private int queueCapacity = 20;
        /**
         * The longest a request waits for a place, or for the verdict it follows. It covers one whole analysis: the
         * first layer takes 4 to 10 seconds, and a case it passes to the second layer took 22 seconds on the showcase
         * engine (the second layer's own limit is 30 seconds). A wait shorter than that refused requests whose
         * verdict was a few seconds away (RL-12, I-25). It is also the longest any synchronous request, a person's
         * too, holds the application's thread for its verdict, whether the flights are on or not (PR-54): past it the
         * request is refused and the analysis goes on. An application on a model slower than this raises it.
         */
        private Duration wait = Duration.ofSeconds(40);
        /** The requests that may pass before the first verdict is in; 0 for none. */
        private int passBudget = 3;
        /** The kinds of operation that may pass (READ, ...); only for a resource the host declared non-sensitive. */
        private List<String> passFamilies = new ArrayList<>(List.of("READ"));
    }

    @Data
    public static class ScopeNarrowing {
        private boolean enabled = true;
        private Duration duration = Duration.ofHours(1);
        private double riskThreshold = 0.7;
    }

    /**
     * docs/agent A5-7 (AG-11e): the calls an agent may make in a minute, for one delegation (one person's work) and for
     * the agent across everyone it acts for. Past a limit the request is slowed down ({@code THROTTLE}: 429 with
     * Retry-After) or the agent is stopped ({@code STOP}: as a BLOCK stops it).
     */
    @Data
    public static class CallLimit {
        private boolean enabled = true;
        private int perDelegationPerMinute = 120;
        private int perAgentPerMinute = 600;
        private OnExceed onExceed = OnExceed.THROTTLE;

        public enum OnExceed {
            THROTTLE,
            STOP
        }
    }

    /**
     * docs/agent A5-7: an agent whose requests in {@code window} were refused at {@code rate} or more, over at least
     * {@code minRequests}, raises an alarm (audited, the accountable person told) once per window.
     */
    @Data
    public static class DenialAlarm {
        private boolean enabled = true;
        private Duration window = Duration.ofMinutes(5);
        private int minRequests = 10;
        private double rate = 0.5;
    }

    /**
     * docs/agent F-1: an ALLOW in force answers an agent's later requests only for the same operation, for at most
     * {@code maxDistinctResources} resources and {@code maxRequests} requests; then the next one is decided again.
     */
    @Data
    public static class AllowReuse {
        private int maxRequests = 10;
        private int maxDistinctResources = 3;
        /**
         * The distinct resources an ALLOW answers when the resource is sensitive (SENSITIVE or CRITICAL); never more than
         * {@code maxDistinctResources}. An agent that reads sensitive records one by one is decided again at each new one.
         */
        private int sensitiveMaxDistinctResources = 1;
    }

    /**
     * docs/agent A5-8: the push endpoint {@code /contexa/api/risk-signals} for Security Event Tokens (OpenID SSF, CAEP,
     * RISC). Off by default; on, it takes the tokens of the configured transmitters addressed to {@code audience}.
     */
    @Data
    public static class RiskSignals {
        private boolean receiverEnabled = false;
        private String audience;
        private List<Transmitter> transmitters = new ArrayList<>();

        /** A transmitter: its issuer and where it publishes its keys. */
        @Data
        public static class Transmitter {
            private String issuer;
            private String jwksUri;
        }
    }

    /**
     * docs/agent B4: the OpenID AuthZEN Authorization API 1.0 evaluation endpoints ({@code {basePath}/access/v1/
     * evaluation}, {@code /evaluations}) and their metadata ({@code /.well-known/authzen-configuration}). Off by
     * default; on, an authenticated caller holding {@code requiredAuthority} (the enforcement point) asks Contexa's
     * decision about a request it received.
     */
    @Data
    public static class Authzen {
        private boolean enabled = false;
        /** Where the evaluation endpoints are served, apart from the application's own paths. */
        private String basePath = "/contexa/authzen";
        /** The authority an enforcement point's credential must hold. */
        private String requiredAuthority = "SCOPE_contexa.authzen";
        /** The decision point's identifier in the metadata (an https URL); null for the request's base address. */
        private String policyDecisionPoint;
        /** The most evaluations one batch request may carry. */
        private int maxEvaluations = 20;
    }

    /** A business objective's contract (A2-1, A2-2). */
    @Data
    public static class ObjectiveContract {
        /** The operations the objective needs, as the {@code @Protectable} actions name them (READ, EXPORT, ...). */
        private List<String> operations = new ArrayList<>();
        /** The resource families it works on, as the {@code @Protectable} categories name them. */
        private List<String> resourceFamilies = new ArrayList<>();
        /** Whether the objective only reads. */
        private boolean readOnly;
        /** Whether the objective may export privileged data. */
        private boolean privilegedExportAllowed;
        /** The most items one export of the objective may carry; empty for no limit. */
        private Integer maxExportItems;
    }

    /** How an agent request with no decision on record is handled at an asynchronous {@code @Protectable} method. */
    public enum UnrecordedAgentRequest {
        /** Decide it in the request, as a {@code @Protectable(sync = true)} method does, and enforce the decision. */
        DECIDE_IN_PLACE,
        /** Let it proceed while it is analysed, as a person's request does. */
        PROCEED
    }

    @Data
    public static class RedisSettings {
        private int timeout = 5000;
        private int updateIntervalSeconds = 30;
    }

    /** How a decision weaker than a minimum-action rule is handled. */
    public enum MinimumActionMode {
        OBSERVE,
        ENFORCE
    }

    @Data
    public static class MinimumActionSettings {
        private MinimumActionMode mode = MinimumActionMode.OBSERVE;
        private IdentityRule identity = new IdentityRule();
        private RuleSwitch newDeviceExport = new RuleSwitch();
        private PolicySatisfactionRule policySatisfaction = new PolicySatisfactionRule();

        /** The rule settings these keys give (contexa.security.zerotrust.minimum-action.*). */
        public MinimumActionRules.Settings toRules() {
            return new MinimumActionRules.Settings(identity.isEnabled(), identity.getMinDeviations(),
                    identity.getMinResourceClass(), newDeviceExport.isEnabled(), policySatisfaction.isEnabled(),
                    policySatisfaction.getAction());
        }
    }

    @Data
    public static class IdentityRule {
        private boolean enabled = true;
        private int minDeviations = 2;
        private String minResourceClass = "SENSITIVE";
    }

    /**
     * P3: the switch and the floor (Q-87: a review; a verification of the user does not supply a missing record). The
     * floor is CHALLENGE or ESCALATE; any other value stops the start-up (N-CONF-1).
     */
    @Data
    public static class PolicySatisfactionRule {
        private boolean enabled = true;
        private String action = "ESCALATE";
    }

    @Data
    public static class RuleSwitch {
        private boolean enabled = true;
    }
}
