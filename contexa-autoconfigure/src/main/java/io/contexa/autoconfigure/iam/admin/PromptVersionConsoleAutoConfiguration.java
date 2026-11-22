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

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.config.TieredLLMProperties;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.components.prompt.version.VersionedPrompts;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleSelector;
import io.contexa.contexacore.std.components.prompt.quality.QualityGateSettings;
import io.contexa.contexacore.std.components.prompt.quality.QualityGateSource;
import io.contexa.contexacore.std.components.prompt.quality.QualityShippedMeasurements;
import io.contexa.contexacore.std.components.prompt.governance.PromptGovernanceReleaseGateService;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageRepository;
import io.contexa.contexaiam.admin.promptquality.cases.PromptQualityCases;
import io.contexa.contexaiam.admin.promptquality.cases.QualityCaseUserDeletionListener;
import io.contexa.contexaiam.admin.promptquality.governance.JdbcPromptReleaseQueryService;
import io.contexa.contexaiam.admin.promptquality.governance.PromptBundleRollbackService;
import io.contexa.contexaiam.admin.promptquality.governance.PromptGovernanceRuntimeCacheInvalidationService;
import io.contexa.contexaiam.admin.promptquality.inspection.JdbcPromptInspectionQueries;
import io.contexa.contexaiam.admin.promptquality.inspection.SealedDecisionReplays;
import io.contexa.contexaiam.admin.promptquality.measure.PromptQualityMeasurements;
import io.contexa.contexaiam.admin.promptquality.measure.PromptQualityResourceClasses;
import io.contexa.contexaiam.admin.promptquality.measure.PromptQualityRunLine;
import io.contexa.contexaiam.admin.promptquality.measure.QualityMeasureLock;
import io.contexa.contexaiam.admin.promptquality.measure.MeasuredQualityGateSource;
import io.contexa.contexaiam.admin.promptquality.measure.QualityAutoMeasurement;
import io.contexa.contexaiam.admin.promptquality.measure.QualityModelSetting;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityCaseApiController;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityCaseScreen;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityNavAdvice;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityNavCounts;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityPageController;
import io.contexa.contexaiam.admin.promptquality.version.JdbcPromptVersionCatalog;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionAudit;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsole;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleController;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionFolderScanner;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionLengthLimits;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionService;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionTrials;
import io.contexa.autoconfigure.core.infra.CoreSchedulerLockAutoConfiguration;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleService;
import net.javacrumbs.shedlock.core.LockProvider;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationListener;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.lang.management.ManagementFactory;
import java.time.Clock;
import java.util.Optional;
import java.util.UUID;

/**
 * The prompt version screens (plan 3.10, 6-5, 6-6): the console that composes what they show, the trials that decide
 * sealed decisions again with two versions, the length limit of the checks before saving, and the controller of the
 * screens and their API. They stand on the versions of the database: without the version service there are no screens.
 * The length limit of the checks is the version service's (PromptVersionAutoConfiguration). The trials stand on the
 * replay of sealed decisions (SealedDecisionReplayAutoConfiguration), which the prompt inspection's switch does not
 * turn off. The labelled cases of the prompt quality measurement and their published sets (quality plan 3.2) stand on the
 * same schema as the versions, and the measurements (quality plan 3.3) on the cases and the replay: they wait in the
 * line of the trials, and one server at a time runs them under the lock of the scheduled work of Contexa. The menu bar
 * of the screens of the prompt quality assurance group and its new screens (quality plan 3.8) stand on the version
 * service too.
 */
@AutoConfiguration(after = {PromptVersionAutoConfiguration.class, PromptGovernanceAutoConfiguration.class,
        PromptInspectionAutoConfiguration.class, SealedDecisionReplayAutoConfiguration.class,
        IamAdminMonitoringAutoConfiguration.class, CoreSchedulerLockAutoConfiguration.class})
@ConditionalOnProperty(prefix = "contexa.prompt.governance", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties(PqaOssQualityProperties.class)
public class PromptVersionConsoleAutoConfiguration {

    /**
     * Quality plan 3.3: the line of this server the trials and the measurements wait in, one after the other on one
     * thread.
     */
    @Bean(name = "contexaPromptQualityRunLine", destroyMethod = "close")
    @ConditionalOnMissingBean
    @ConditionalOnBean(PromptVersionService.class)
    public PromptQualityRunLine promptQualityRunLine() {
        return new PromptQualityRunLine();
    }

    /**
     * Plan 6-5: the trials, one at a time in the line of the measurements; a trial a stop left unfinished is marked
     * failed.
     */
    @Bean(name = "contexaPromptVersionTrials", destroyMethod = "close")
    @ConditionalOnMissingBean
    @ConditionalOnBean({PromptVersionService.class, SealedDecisionReplays.class, PromptQualityRunLine.class})
    public PromptVersionTrials promptVersionTrials(@Qualifier("contexaJdbcTemplate") JdbcTemplate jdbcTemplate,
                                                   PromptVersionService versions, SealedDecisionReplays replays,
                                                   PromptQualityRunLine contexaPromptQualityRunLine,
                                                   ObjectProvider<PromptVersionAudit> audit) {
        PromptVersionTrials trials = new PromptVersionTrials(() -> jdbcTemplate, versions,
                (actor, packageId, version) -> replays.replayPackage(actor, packageId,
                        new SealedDecisionReplays.ReplayRequest(version, null, null, null))
                        .map(replayed -> PromptVersionTrials.replayed(replayed.result())),
                contexaPromptQualityRunLine.executor(), audit.getIfAvailable(PromptVersionAudit::none),
                Clock.systemUTC());
        trials.closeInterrupted();
        return trials;
    }

    /**
     * Quality plan 3.2: the labelled cases and their published sets, by the scope of the versions; the default set is
     * read from the product when first needed. A change of several rows runs in one transaction of Contexa's own.
     */
    @Bean(name = "contexaPromptQualityCases")
    @ConditionalOnMissingBean
    @ConditionalOnBean(PromptVersionService.class)
    public PromptQualityCases promptQualityCases(@Qualifier("contexaJdbcTemplate") JdbcTemplate jdbcTemplate,
                                                 @Qualifier("contexaObjectMapper") ObjectMapper objectMapper,
                                                 PqaOssQualityProperties properties,
                                                 ObjectProvider<PromptVersionAudit> audit,
                                                 @Qualifier("contexaTransactionManager")
                                                 ObjectProvider<PlatformTransactionManager> transactionManager) {
        PlatformTransactionManager manager = transactionManager.getIfAvailable();
        return new PromptQualityCases(() -> jdbcTemplate, objectMapper, properties.isTwoPersonConfirmation(),
                audit.getIfAvailable(PromptVersionAudit::none), Clock.systemUTC(),
                manager != null ? new TransactionTemplate(manager) : null, null);
    }

    /**
     * Quality plan 3.3: the measurements of a version on a published case set. Each case is replayed from its input
     * built in memory, with its baselines and context format, and the second pass is asked with the second layer's
     * own model after an ESCALATE. The servers of one database share the lock store of the scheduled work of Contexa
     * (ShedLock), so one of them runs measurements at a time; without it this server runs them alone.
     */
    @Bean(name = "contexaPromptQualityMeasurements", destroyMethod = "close")
    @ConditionalOnMissingBean
    @ConditionalOnBean({PromptVersionService.class, SealedDecisionReplays.class, PromptQualityCases.class,
            PromptQualityRunLine.class})
    public PromptQualityMeasurements promptQualityMeasurements(
            @Qualifier("contexaJdbcTemplate") JdbcTemplate jdbcTemplate, PromptVersionService versions,
            PromptQualityCases contexaPromptQualityCases, SealedDecisionReplays replays,
            PromptQualityRunLine contexaPromptQualityRunLine, PqaOssQualityProperties properties,
            ObjectProvider<LockProvider> lockProviders, ObjectProvider<TieredStrategyProperties> tiered,
            ObjectProvider<TieredLLMProperties> models, ObjectProvider<SecurityZeroTrustProperties> zeroTrust,
            @Qualifier("contexaObjectMapper") ObjectMapper objectMapper) {
        LockProvider lockProvider = lockProviders.getIfUnique();
        QualityMeasureLock lock = lockProvider != null
                ? QualityMeasureLock.shedLock(lockProvider, PromptQualityMeasurements.LOCK_NAME, Clock.systemUTC())
                : QualityMeasureLock.local();
        PromptQualityMeasurements measurements = new PromptQualityMeasurements(() -> jdbcTemplate, versions,
                contexaPromptQualityCases,
                (actor, given, contextFormat, version, userBaseline, organizationBaseline) -> replays.replayGiven(actor,
                        given, contextFormat, new SealedDecisionReplays.ReplayRequest(version, null, userBaseline,
                                organizationBaseline, true)).result(),
                contexaPromptQualityRunLine, lock,
                () -> QualityModelSetting.settings(tiered.getIfAvailable(), models.getIfAvailable(),
                        zeroTrust.getIfAvailable()),
                () -> QualityModelSetting.closingRules(tiered.getIfAvailable()),
                properties.getMeasurement().toSettings(), objectMapper, Clock.systemUTC(),
                ManagementFactory.getRuntimeMXBean().getName() + "#" + UUID.randomUUID().toString().substring(0, 8));
        measurements.startLookingForWork();
        return measurements;
    }

    /**
     * Quality plan 3.4: the measurements Contexa shipped of its own versions on the default case set; none when the
     * product ships none.
     */
    @Bean(name = "contexaQualityShippedMeasurements")
    @ConditionalOnMissingBean
    public QualityShippedMeasurements qualityShippedMeasurements() {
        return QualityShippedMeasurements.contexa();
    }

    /**
     * Quality plan 3.4: what the quality gate of the release gate reads, from the store of the measurements. Without the
     * measurement runner (no replay of decisions in this application) every version cannot be measured.
     */
    @Bean(name = "contexaQualityGateSource")
    @ConditionalOnMissingBean(QualityGateSource.class)
    @ConditionalOnBean({PromptVersionService.class, PromptQualityCases.class})
    public MeasuredQualityGateSource qualityGateSource(@Qualifier("contexaJdbcTemplate") JdbcTemplate jdbcTemplate,
                                                       PromptVersionService versions,
                                                       PromptQualityCases contexaPromptQualityCases,
                                                       ObjectProvider<PromptQualityMeasurements> measurements,
                                                       QualityShippedMeasurements contexaQualityShippedMeasurements) {
        return new MeasuredQualityGateSource(() -> jdbcTemplate, versions, contexaPromptQualityCases,
                measurements::getIfAvailable, contexaQualityShippedMeasurements);
    }

    /**
     * Quality P46: the cases and the metrics by resource class, beside the decisions of the operation of each class;
     * the comparison of two versions class by class reads the measurements the quality gate reads.
     */
    @Bean(name = "contexaPromptQualityResourceClasses")
    @ConditionalOnMissingBean
    @ConditionalOnBean(PromptQualityCases.class)
    public PromptQualityResourceClasses promptQualityResourceClasses(
            @Qualifier("contexaJdbcTemplate") JdbcTemplate jdbcTemplate, PromptQualityCases contexaPromptQualityCases,
            ObjectProvider<PromptQualityMeasurements> measurements, ObjectProvider<QualityGateSource> gateSources) {
        return new PromptQualityResourceClasses(() -> jdbcTemplate, contexaPromptQualityCases,
                measurements::getIfAvailable, gateSources::getIfUnique, Clock.systemUTC());
    }

    /**
     * Quality plan 3.4: the measurements Contexa starts by itself, of the version that decides outside the release gate
     * and of the version in use with no measurement; the servers of one database decide them under the lock store of
     * the scheduled work of Contexa, so one of them starts each.
     */
    @Bean(name = "contexaQualityAutoMeasurement", destroyMethod = "close")
    @ConditionalOnMissingBean
    @ConditionalOnBean({PromptVersionService.class, PromptQualityCases.class})
    public QualityAutoMeasurement qualityAutoMeasurement(@Qualifier("contexaJdbcTemplate") JdbcTemplate jdbcTemplate,
                                                         PromptVersionService versions,
                                                         PromptQualityCases contexaPromptQualityCases,
                                                         ObjectProvider<PromptQualityMeasurements> measurements,
                                                         ObjectProvider<PromptBundleSelector> selector,
                                                         QualityShippedMeasurements contexaQualityShippedMeasurements,
                                                         ObjectProvider<LockProvider> lockProviders) {
        LockProvider lockProvider = lockProviders.getIfUnique();
        return new QualityAutoMeasurement(() -> jdbcTemplate, versions, contexaPromptQualityCases,
                measurements::getIfAvailable, new JdbcPromptVersionCatalog(versions, () -> jdbcTemplate,
                selector::getIfUnique), contexaQualityShippedMeasurements,
                lockProvider != null ? QualityMeasureLock.shedLock(lockProvider, QualityAutoMeasurement.LOCK_NAME,
                        Clock.systemUTC()) : QualityMeasureLock.local());
    }

    /**
     * Quality plan 3.4: once the application is ready, the versions that decide outside the gate and the versions in
     * use with no measurement are measured, on the measurer's own thread.
     */
    @Bean(name = "contexaQualityAutoMeasurementStart")
    @ConditionalOnBean(QualityAutoMeasurement.class)
    public ApplicationListener<ApplicationReadyEvent> qualityAutoMeasurementStart(
            QualityAutoMeasurement contexaQualityAutoMeasurement) {
        return ready -> contexaQualityAutoMeasurement.measureDecidingVersionsLater();
    }

    /** Quality plan 3.2: the deletion of a person reaches the labelled cases whose decision is the person's. */
    @Bean(name = "contexaQualityCaseUserDeletionListener")
    @ConditionalOnMissingBean
    @ConditionalOnBean(PromptQualityCases.class)
    public QualityCaseUserDeletionListener qualityCaseUserDeletionListener(PromptQualityCases contexaPromptQualityCases) {
        return new QualityCaseUserDeletionListener(contexaPromptQualityCases);
    }

    @Bean(name = "contexaPromptVersionConsole")
    @ConditionalOnMissingBean
    @ConditionalOnBean(PromptVersionService.class)
    public PromptVersionConsole promptVersionConsole(PromptVersionService versions,
                                                     ObjectProvider<PromptVersionTrials> trials,
                                                     ObjectProvider<PromptBundleSelector> selector,
                                                     @Qualifier("contexaJdbcTemplate") JdbcTemplate jdbcTemplate,
                                                     ObjectProvider<JdbcPromptReleaseQueryService> releases,
                                                     ObjectProvider<PromptGovernanceReleaseGateService> gate,
                                                     ObjectProvider<PromptGovernanceRuntimeCacheInvalidationService> invalidation,
                                                     ObjectProvider<PromptBundleRollbackService> rollbacks,
                                                     ObjectProvider<JdbcPromptInspectionQueries> sealed,
                                                     ObjectProvider<ZeroTrustConsoleService> decisions,
                                                     ObjectProvider<PromptVersionFolderScanner> folder,
                                                     ObjectProvider<PromptVersionLengthLimits> limits,
                                                     ObjectProvider<PromptVersionAudit> audit, Environment environment,
                                                     ObjectProvider<VersionedPrompts> versionedPrompts,
                                                     ObjectProvider<SealedDecisionReplays> replays,
                                                     ObjectProvider<PromptQualityMeasurements> measurements,
                                                     ObjectProvider<QualityAutoMeasurement> autoMeasurement) {
        PromptVersionConsole console = new PromptVersionConsole(versions, trials::getIfAvailable, selector::getIfUnique, () -> jdbcTemplate,
                releases::getIfAvailable, gate::getIfAvailable, invalidation::getIfAvailable, rollbacks::getIfAvailable,
                sealed::getIfAvailable, decisions::getIfAvailable, folder::getIfAvailable,
                environment.getProperty("contexa.prompt.versions.directory"),
                () -> {
                    PromptVersionLengthLimits limit = limits.getIfAvailable();
                    return limit != null ? limit.get() : null;
                },
                audit.getIfAvailable(PromptVersionAudit::none), Clock.systemUTC());
        // Plan 3.11: the prompts other than the security decision show their finished prompt with an example input.
        console.setVersionedPrompts(versionedPrompts.getIfAvailable());
        // Quality plan 3.4: "save and measure" measures on the case set the measurements of the scope run on.
        console.setMeasureStarter(() -> {
            PromptQualityMeasurements runner = measurements.getIfAvailable();
            QualityAutoMeasurement sets = autoMeasurement.getIfAvailable();
            return runner == null || sets == null ? null : (scope, prompt, number, actor) -> {
                try {
                    return runner.start(scope, prompt, number, sets.caseSet(scope, prompt).id(), null, actor);
                }
                catch (PromptQualityMeasurements.RefusedException refused) {
                    throw new PromptVersionConsole.RefusedException("MEASURE_" + refused.refusal().name());
                }
            };
        });
        // Plan 3.10 (2): the finished prompt draws the latest sealed decision again with the version, as a replay does.
        // K71: beside it, the state of the sealed package, as a replay tells it.
        console.setSealedDrawing(() -> {
            SealedDecisionReplays drawing = replays.getIfAvailable();
            return drawing == null ? null : new PromptVersionConsole.SealedDrawing() {
                @Override
                public Optional<String> userPrompt(String packageId, String version) {
                    return drawing.drawPackage(packageId, version).map(drawn -> drawn.drawing().userPrompt());
                }

                @Override
                public Optional<String> integrity(String packageId) {
                    return drawing.integrity(packageId).map(Enum::name);
                }
            };
        });
        return console;
    }

    @Bean(name = "contexaPromptVersionConsoleController")
    @ConditionalOnMissingBean
    @ConditionalOnBean(PromptVersionConsole.class)
    public PromptVersionConsoleController promptVersionConsoleController(PromptVersionConsole console,
                                                                         MessageSource messageSource,
                                                                         @Qualifier("contexaObjectMapper") ObjectMapper objectMapper) {
        return new PromptVersionConsoleController(console, messageSource, objectMapper);
    }

    /**
     * Quality plan 3.8: the counts beside the menus of the bar on top of the screens of the prompt quality assurance
     * group, read from the services of the screens when a page draws the bar; each service may be absent.
     */
    @Bean(name = "contexaPromptQualityNavCounts")
    @ConditionalOnMissingBean
    @ConditionalOnBean(PromptVersionService.class)
    public PromptQualityNavCounts promptQualityNavCounts(ObjectProvider<PromptQualityCases> cases,
                                                         ObjectProvider<PromptQualityMeasurements> measurements,
                                                         ObjectProvider<PromptVersionTrials> trials,
                                                         ObjectProvider<PromptVersionService> versions,
                                                         ObjectProvider<SealedEvidencePackageRepository> sealed) {
        return new PromptQualityNavCounts(cases::getIfAvailable, measurements::getIfAvailable, trials::getIfAvailable,
                versions::getIfAvailable, sealed::getIfUnique, Clock.systemUTC());
    }

    /** Quality plan 3.8: the menu bar for every page of the group, so a screen only calls the bar fragment. */
    @Bean(name = "contexaPromptQualityNavAdvice")
    @ConditionalOnMissingBean
    @ConditionalOnBean(PromptQualityNavCounts.class)
    public PromptQualityNavAdvice promptQualityNavAdvice(PromptQualityNavCounts contexaPromptQualityNavCounts) {
        return new PromptQualityNavAdvice(contexaPromptQualityNavCounts);
    }

    /** Quality plan 3.2, 3.3: the screens of the labelled cases and of measure and compare. */
    @Bean(name = "contexaPromptQualityPageController")
    @ConditionalOnMissingBean
    @ConditionalOnBean(PromptVersionService.class)
    public PromptQualityPageController promptQualityPageController(MessageSource messageSource,
                                                                   @Qualifier("contexaObjectMapper") ObjectMapper objectMapper) {
        return new PromptQualityPageController(messageSource, objectMapper);
    }

    /**
     * Quality plan 3.2, P46: what the screen of the labelled cases shows, from the cases, the measurements, the resource
     * classes and the version in use; the targets of roots and the level of the comparisons are the gate's settings.
     */
    @Bean(name = "contexaPromptQualityCaseScreen")
    @ConditionalOnMissingBean
    @ConditionalOnBean(PromptQualityCases.class)
    public PromptQualityCaseScreen promptQualityCaseScreen(PromptQualityCases contexaPromptQualityCases,
                                                           ObjectProvider<PromptQualityMeasurements> measurements,
                                                           ObjectProvider<PromptQualityResourceClasses> classes,
                                                           ObjectProvider<PromptVersionConsole> console,
                                                           ObjectProvider<SealedEvidencePackageRepository> sealed,
                                                           PqaOssQualityProperties properties) {
        PqaOssQualityProperties.Gate gate = properties.getGate();
        return new PromptQualityCaseScreen(contexaPromptQualityCases, measurements::getIfAvailable,
                classes::getIfAvailable, console::getIfAvailable, sealed::getIfUnique,
                new QualityGateSettings(gate.getModelLessLimit(), gate.getSignificance(), gate.getMinimumStopRoots(),
                        gate.getMinimumAllowRoots()), Clock.systemUTC());
    }

    /** Quality plan 3.2: the JSON of the screen of the labelled cases. */
    @Bean(name = "contexaPromptQualityCaseApiController")
    @ConditionalOnMissingBean
    @ConditionalOnBean(PromptQualityCaseScreen.class)
    public PromptQualityCaseApiController promptQualityCaseApiController(
            PromptQualityCaseScreen contexaPromptQualityCaseScreen) {
        return new PromptQualityCaseApiController(contexaPromptQualityCaseScreen);
    }
}
