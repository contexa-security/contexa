package io.contexa.showcase.portal.orchestrator;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.business.internal.InternalContextSigner;
import io.contexa.showcase.portal.anatomy.AnatomyStore;
import io.contexa.showcase.portal.anatomy.BeforeSend;
import io.contexa.showcase.portal.benchmark.BenchmarkService;
import io.contexa.showcase.portal.benchmark.BenchmarkView;
import io.contexa.showcase.portal.combination.CombinationService;
import io.contexa.showcase.portal.combination.CombinationStore;
import io.contexa.showcase.portal.hook.HookStore;
import io.contexa.showcase.portal.live.BaselineEvidence;
import io.contexa.showcase.portal.live.DecisionWaits;
import io.contexa.showcase.portal.live.LiveAllotment;
import io.contexa.showcase.portal.live.LiveGate;
import io.contexa.showcase.portal.live.LiveGateWatch;
import io.contexa.showcase.portal.live.LiveQuota;
import io.contexa.showcase.portal.live.LiveRuns;
import io.contexa.showcase.portal.live.TurnstileVerifier;
import io.contexa.showcase.portal.measured.MeasuredCases;
import io.contexa.showcase.portal.replay.PairCatalog;
import io.contexa.showcase.portal.replay.ReplayRecorder;
import io.contexa.showcase.portal.replay.ReplayStore;
import io.contexa.showcase.portal.replay.ReplayViews;
import io.contexa.showcase.portal.scenario.ScenarioCatalog;
import io.contexa.showcase.portal.scenario.ScenarioDefinition;
import io.contexa.showcase.portal.scoring.RunScores;
import io.contexa.showcase.portal.spec.ExecutionSpecStore;
import io.contexa.showcase.portal.spec.ScoringContract;
import io.contexa.showcase.portal.teaser.TeaserService;
import io.contexa.showcase.portal.template.CloneVerifier;
import io.contexa.showcase.portal.template.TemplateCurrency;
import io.contexa.showcase.portal.template.TemplateLearner;
import io.contexa.showcase.portal.template.TemplateMaintainer;
import io.contexa.showcase.portal.template.TemplateStore;
import org.slf4j.LoggerFactory;
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

    /** The template a run may clone: learned under the versions in force (docs/showcase/계획대조-검수.md N-8). */
    @Bean
    TemplateCurrency templateCurrency(WorkloadAdmin admin, TemplateStore templateStore) {
        return new TemplateCurrency(admin, templateStore, Clock.systemUTC());
    }

    @Bean
    RunOrchestrator runOrchestrator(ControlEndpoints endpoints, WorkloadAdmin admin, InternalContextSigner signer,
                                    RunStore runStore, TemplateCurrency templateCurrency, ExecutionSpecStore specs,
                                    ScoringContract contract, ObjectMapper objectMapper,
                                    AnatomyStore anatomies) {
        return new RunOrchestrator(endpoints, admin, signer, runStore, templateCurrency, specs, contract,
                objectMapper, anatomies);
    }

    @Bean
    CleanupRetrier cleanupRetrier(RunStore runStore, WorkloadAdmin admin, ObjectMapper objectMapper) {
        return new CleanupRetrier(runStore, admin, objectMapper, Clock.systemUTC());
    }

    /** Repeats failed or abandoned run clean-ups every five minutes (plan section 8, N-6). */
    @Bean(destroyMethod = "shutdownNow")
    ScheduledExecutorService cleanupRetrierSchedule(CleanupRetrier retrier) {
        ScheduledExecutorService schedule = Executors.newSingleThreadScheduledExecutor(runnable -> {
            Thread thread = new Thread(runnable, "showcase-cleanup-retrier");
            thread.setDaemon(true);
            return thread;
        });
        schedule.scheduleWithFixedDelay(() -> {
            try {
                retrier.run();
            } catch (RuntimeException e) {
                // The next pass five minutes later tries again.
                LoggerFactory.getLogger(CleanupRetrier.class).error("Clean-up retry pass failed", e);
            }
        }, 2, 5, TimeUnit.MINUTES);
        return schedule;
    }

    @Bean
    ReplayRecorder replayRecorder(PairCatalog pairs, ScenarioCatalog scenarios, RunOrchestrator orchestrator,
                                  ReplayStore replayStore) {
        return new ReplayRecorder(pairs, scenarios, orchestrator, replayStore, Clock.systemUTC());
    }

    /**
     * Live runs of visitors (P3 single space, P4 spaces and gate); off unless showcase.live.enabled=true. The limits
     * are the plan's values (docs/showcase approvals Q-26). The start rate keeps the engine under the model provider's
     * tokens-per-minute limit: 12 starts a minute fit a key of 200,000 tokens a minute (a run uses about 6,000 to
     * 14,000 tokens; docs/showcase/계획대조-검수.md N-1); raise it together with the provider limit. A forced
     * decision (Q-23) is only for checking the flows on a development stack.
     */
    @Bean(destroyMethod = "close")
    @ConditionalOnProperty(name = "showcase.live.enabled", havingValue = "true")
    LiveRuns liveRuns(RunOrchestrator orchestrator, ScenarioCatalog scenarios,
                      @Value("${showcase.live.max-concurrent:50}") int maxConcurrent,
                      @Value("${showcase.live.max-queue:200}") int maxQueue,
                      @Value("${showcase.live.starts-per-minute:12}") int startsPerMinute,
                      @Value("${showcase.live.space-lifetime:PT30M}") Duration lifetime,
                      @Value("${showcase.live.space-inactivity:PT15M}") Duration inactivity,
                      @Value("${showcase.live.scenarios:all}") String scenarioKeys,
                      @Value("${showcase.live.dev-forced-action:}") String forcedAction) {
        // One setting decides which designed cases visitors can run, on every screen (F-25): "all" (or empty) is
        // every case of the catalog, a list limits them.
        List<String> keys = scenarioKeys.isBlank() || "all".equalsIgnoreCase(scenarioKeys.trim())
                ? scenarios.all().stream().map(ScenarioDefinition::key).toList()
                : Arrays.stream(scenarioKeys.split(",")).map(String::trim).filter(key -> !key.isEmpty()).toList();
        keys.forEach(key -> scenarios.find(key)
                .orElseThrow(() -> new IllegalStateException("Unknown live scenario " + key)));
        return new LiveRuns(orchestrator::run, new LiveRuns.Settings(maxConcurrent, maxQueue, startsPerMinute, lifetime,
                inactivity, keys, forcedAction.isBlank() ? null : forcedAction), Clock.systemUTC());
    }

    /** Starts queued live runs as soon as the concurrency and the start rate allow, checked every second. */
    @Bean(destroyMethod = "shutdownNow")
    @ConditionalOnProperty(name = "showcase.live.enabled", havingValue = "true")
    ScheduledExecutorService liveDispatcher(LiveRuns liveRuns) {
        ScheduledExecutorService dispatcher = Executors.newSingleThreadScheduledExecutor(runnable -> {
            Thread thread = new Thread(runnable, "showcase-live-dispatcher");
            thread.setDaemon(true);
            return thread;
        });
        dispatcher.scheduleWithFixedDelay(liveRuns::dispatch, 1, 1, TimeUnit.SECONDS);
        return dispatcher;
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
    BaselineEvidence baselineEvidence(NamedParameterJdbcTemplate jdbc) {
        return new BaselineEvidence(jdbc);
    }

    @Bean
    @ConditionalOnProperty(name = "showcase.live.enabled", havingValue = "true")
    TeaserService teaserService(NamedParameterJdbcTemplate jdbc, HookStore hookStore, AnatomyStore anatomies,
                                BenchmarkService benchmarkService, TemplateCurrency templateCurrency,
                                ScenarioCatalog scenarioCatalog, ObjectMapper objectMapper) {
        return new TeaserService(jdbc, hookStore, anatomies, benchmarkService, templateCurrency, scenarioCatalog,
                objectMapper, Clock.systemUTC());
    }

    @Bean
    @ConditionalOnProperty(name = "showcase.live.enabled", havingValue = "true")
    DecisionWaits decisionWaits(NamedParameterJdbcTemplate jdbc, BenchmarkService benchmarkService) {
        return new DecisionWaits(jdbc, () -> benchmarkService.view(null).map(BenchmarkView::spec)
                .map(BenchmarkView.Spec::settingHash), Clock.systemUTC());
    }

    @Bean
    @ConditionalOnProperty(name = "showcase.live.enabled", havingValue = "true")
    MeasuredCases measuredCases(NamedParameterJdbcTemplate jdbc, RunScores runScores,
                                BenchmarkService benchmarkService) {
        return new MeasuredCases(jdbc, runScores, () -> benchmarkService.view(null).map(BenchmarkView::spec)
                .map(BenchmarkView.Spec::settingHash), Clock.systemUTC());
    }

    @Bean
    @ConditionalOnProperty(name = "showcase.live.enabled", havingValue = "true")
    BeforeSend beforeSend(NamedParameterJdbcTemplate jdbc, AnatomyStore anatomies, TemplateCurrency templateCurrency,
                          ObjectMapper objectMapper, ReplayViews replayViews) {
        return new BeforeSend(jdbc, anatomies, templateCurrency, objectMapper, replayViews);
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
                      LiveQuota quota, LiveRuns liveRuns, LiveGateWatch watch, TemplateCurrency templateCurrency) {
        return new LiveGate(combinations, turnstile, allotment, quota, liveRuns, watch, templateCurrency);
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
    CombinationService combinationService(WorkloadAdmin admin, TemplateCurrency templateCurrency,
                                          ScoringContract contract, CombinationStore combinationStore,
                                          ReplayStore replayStore, ReplayViews replayViews) {
        return new CombinationService(admin, templateCurrency, contract, combinationStore, replayStore, replayViews,
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

    /**
     * Learns a new template whenever none was learned under the versions in force (plan P1 "automate re-learning",
     * N-8). On in production; a development stack learns through the operator API instead.
     */
    @Bean(initMethod = "start", destroyMethod = "close")
    @ConditionalOnProperty(name = "showcase.templates.auto-learn", havingValue = "true")
    TemplateMaintainer templateMaintainer(ScenarioCatalog scenarios, WorkloadAdmin admin,
                                          TemplateCurrency templateCurrency, TemplateStore templateStore,
                                          TemplateLearner learner) {
        return new TemplateMaintainer(scenarios, admin::protagonists, templateCurrency, templateStore, learner::learn,
                Clock.systemUTC());
    }
}
