package io.contexa.showcase.portal.orchestrator;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.business.internal.InternalContextSigner;
import io.contexa.showcase.portal.combination.CombinationService;
import io.contexa.showcase.portal.combination.CombinationStore;
import io.contexa.showcase.portal.live.LiveAllotment;
import io.contexa.showcase.portal.live.LiveGate;
import io.contexa.showcase.portal.live.LiveGateWatch;
import io.contexa.showcase.portal.live.LiveQuota;
import io.contexa.showcase.portal.live.LiveRuns;
import io.contexa.showcase.portal.live.TurnstileVerifier;
import io.contexa.showcase.portal.replay.ReplayViews;
import io.contexa.showcase.portal.replay.PairCatalog;
import io.contexa.showcase.portal.replay.ReplayRecorder;
import io.contexa.showcase.portal.replay.ReplayStore;
import io.contexa.showcase.portal.scenario.ScenarioCatalog;
import io.contexa.showcase.portal.spec.ExecutionSpecStore;
import io.contexa.showcase.portal.spec.ScoringContract;
import io.contexa.showcase.portal.template.CloneVerifier;
import io.contexa.showcase.portal.template.TemplateLearner;
import io.contexa.showcase.portal.template.TemplateStore;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * The orchestration part of the portal, active when the control addresses are configured
 * (showcase.portal.controls.*, docs/showcase/ADR.md ADR-20).
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(prefix = "showcase.portal.controls", name = "d")
public class OrchestrationConfiguration {

    @Bean
    InternalContextSigner portalInternalContextSigner(@Value("${showcase.internal.signing-key:}") String signingKey) {
        return new InternalContextSigner(signingKey);
    }

    @Bean
    WorkloadAdmin workloadAdmin(ControlEndpoints endpoints, InternalContextSigner signer, ObjectMapper objectMapper) {
        return new WorkloadAdmin(endpoints, signer, objectMapper);
    }

    @Bean
    RunStore runStore(NamedParameterJdbcTemplate jdbc, ObjectMapper objectMapper) {
        return new RunStore(jdbc, objectMapper);
    }

    @Bean
    TemplateStore templateStore(NamedParameterJdbcTemplate jdbc, ObjectMapper objectMapper) {
        return new TemplateStore(jdbc, objectMapper);
    }

    @Bean
    RunOrchestrator runOrchestrator(ControlEndpoints endpoints, WorkloadAdmin admin, InternalContextSigner signer,
                                    RunStore runStore, TemplateStore templateStore, ExecutionSpecStore specs,
                                    ScoringContract contract, ObjectMapper objectMapper) {
        return new RunOrchestrator(endpoints, admin, signer, runStore, templateStore, specs, contract, objectMapper);
    }

    @Bean
    ReplayRecorder replayRecorder(PairCatalog pairs, ScenarioCatalog scenarios, RunOrchestrator orchestrator,
                                  ReplayStore replayStore) {
        return new ReplayRecorder(pairs, scenarios, orchestrator, replayStore, Clock.systemUTC());
    }

    /**
     * Live runs of visitors (P3 single space, P4 spaces and gate); off unless showcase.live.enabled=true. The limits
     * are the plan's values (docs/showcase approvals Q-26). A forced decision (Q-23) is only for checking the flows on a
     * development stack.
     */
    @Bean(destroyMethod = "close")
    @ConditionalOnProperty(name = "showcase.live.enabled", havingValue = "true")
    LiveRuns liveRuns(RunOrchestrator orchestrator, ScenarioCatalog scenarios,
                      @Value("${showcase.live.max-concurrent:50}") int maxConcurrent,
                      @Value("${showcase.live.max-queue:200}") int maxQueue,
                      @Value("${showcase.live.space-lifetime:PT30M}") Duration lifetime,
                      @Value("${showcase.live.space-inactivity:PT15M}") Duration inactivity,
                      @Value("${showcase.live.scenarios:}") String scenarioKeys,
                      @Value("${showcase.live.dev-forced-action:}") String forcedAction) {
        List<String> keys = Arrays.stream(scenarioKeys.split(",")).map(String::trim)
                .filter(key -> !key.isEmpty()).toList();
        keys.forEach(key -> scenarios.find(key)
                .orElseThrow(() -> new IllegalStateException("Unknown live scenario " + key)));
        return new LiveRuns(orchestrator::run, new LiveRuns.Settings(maxConcurrent, maxQueue, lifetime, inactivity, keys,
                forcedAction.isBlank() ? null : forcedAction), Clock.systemUTC());
    }

    /** Ends expired visitor spaces every 30 seconds. */
    @Bean(destroyMethod = "shutdownNow")
    @ConditionalOnProperty(name = "showcase.live.enabled", havingValue = "true")
    ScheduledExecutorService liveSpaceSweeper(LiveRuns liveRuns) {
        ScheduledExecutorService sweeper = Executors.newSingleThreadScheduledExecutor(runnable -> {
            Thread thread = new Thread(runnable, "showcase-live-sweeper");
            thread.setDaemon(true);
            return thread;
        });
        sweeper.scheduleWithFixedDelay(liveRuns::sweep, 30, 30, TimeUnit.SECONDS);
        return sweeper;
    }

    @Bean
    @ConditionalOnProperty(name = "showcase.live.enabled", havingValue = "true")
    TurnstileVerifier turnstileVerifier(@Value("${showcase.turnstile.enabled:false}") boolean enabled,
                                        @Value("${showcase.turnstile.site-key:}") String siteKey,
                                        @Value("${showcase.turnstile.secret-key:}") String secret,
                                        @Value("${showcase.turnstile.hostnames:}") String hostnames,
                                        @Value("${showcase.production:false}") boolean production,
                                        ObjectMapper objectMapper) {
        return new TurnstileVerifier(enabled, siteKey, secret, Set.copyOf(Arrays.stream(hostnames.split(","))
                .map(String::trim).filter(host -> !host.isEmpty()).toList()),
                URI.create("https://challenges.cloudflare.com/turnstile/v0/siteverify"), production, objectMapper);
    }

    @Bean
    @ConditionalOnProperty(name = "showcase.live.enabled", havingValue = "true")
    LiveQuota liveQuota(NamedParameterJdbcTemplate jdbc,
                        @Value("${showcase.internal.signing-key:}") String signingKey,
                        @Value("${showcase.live.visitor-daily:10}") int visitorDaily,
                        @Value("${showcase.live.address-daily:30}") int addressDaily) {
        return new LiveQuota(jdbc, signingKey, visitorDaily, addressDaily, Clock.systemUTC());
    }

    @Bean
    @ConditionalOnProperty(name = "showcase.live.enabled", havingValue = "true")
    LiveAllotment liveAllotment(NamedParameterJdbcTemplate jdbc, Measurements.Prices prices,
                                @Value("${showcase.live.monthly-budget-usd:30}") double monthlyBudget) {
        return new LiveAllotment(jdbc, prices, monthlyBudget, Clock.systemUTC());
    }

    @Bean
    @ConditionalOnProperty(name = "showcase.live.enabled", havingValue = "true")
    LiveGate liveGate(CombinationService combinations, TurnstileVerifier turnstile, LiveAllotment allotment,
                      LiveQuota quota, LiveRuns liveRuns, LiveGateWatch watch) {
        return new LiveGate(combinations, turnstile, allotment, quota, liveRuns, watch);
    }

    /** Refusals of the gate by reason, with one error log in an hour that reaches the alert level (P5-SEC-07). */
    @Bean
    @ConditionalOnProperty(name = "showcase.live.enabled", havingValue = "true")
    LiveGateWatch liveGateWatch(@Value("${showcase.live.refusal-alert-per-hour:300}") int alertPerHour) {
        return new LiveGateWatch(alertPerHour, Clock.systemUTC());
    }

    @Bean
    CombinationStore combinationStore(NamedParameterJdbcTemplate jdbc) {
        return new CombinationStore(jdbc);
    }

    @Bean
    CombinationService combinationService(WorkloadAdmin admin, TemplateStore templateStore, ScoringContract contract,
                                          CombinationStore combinationStore, ReplayStore replayStore,
                                          ReplayViews replayViews) {
        return new CombinationService(admin, templateStore, contract, combinationStore, replayStore, replayViews,
                Clock.systemUTC());
    }

    @Bean
    CloneVerifier cloneVerifier(WorkloadAdmin admin, TemplateStore templateStore, ObjectMapper objectMapper) {
        return new CloneVerifier(admin, templateStore, objectMapper);
    }

    @Bean
    IsolationSmoke isolationSmoke(RunOrchestrator orchestrator, ScenarioCatalog catalog, WorkloadAdmin admin,
                                  CloneVerifier cloneVerifier, ControlEndpoints endpoints, InternalContextSigner signer,
                                  ObjectMapper objectMapper) {
        return new IsolationSmoke(orchestrator, catalog, admin, cloneVerifier, endpoints, signer, objectMapper);
    }

    /** Model prices per one million tokens (OpenAI standard tier price list read on 2026-10-05). */
    @Bean
    Measurements.Prices measurementPrices(
                              @Value("${showcase.portal.pricing.chat-input:0.05}") double chatInput,
                              @Value("${showcase.portal.pricing.chat-output:0.40}") double chatOutput,
                              @Value("${showcase.portal.pricing.embedding-input:0.02}") double embeddingInput,
                              @Value("${showcase.portal.pricing.source:OpenAI standard tier price list, 2026-10-05}")
                              String source) {
        return new Measurements.Prices(chatInput, chatOutput, embeddingInput, source);
    }

    @Bean
    Measurements measurements(NamedParameterJdbcTemplate jdbc, Measurements.Prices prices) {
        return new Measurements(jdbc, prices);
    }

    @Bean
    TemplateLearner templateLearner(ControlEndpoints endpoints, WorkloadAdmin admin, InternalContextSigner signer,
                                    TemplateStore templateStore, RunStore runStore, ObjectMapper objectMapper) {
        return new TemplateLearner(endpoints, admin, signer, templateStore, runStore, objectMapper);
    }
}
