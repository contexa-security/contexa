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
import io.contexa.contexacore.std.components.prompt.governance.PromptGovernanceReleaseGateService;
import io.contexa.contexaiam.admin.promptquality.cases.PromptQualityCases;
import io.contexa.contexaiam.admin.promptquality.cases.QualityCaseUserDeletionListener;
import io.contexa.contexaiam.admin.promptquality.governance.JdbcPromptReleaseQueryService;
import io.contexa.contexaiam.admin.promptquality.governance.PromptBundleRollbackService;
import io.contexa.contexaiam.admin.promptquality.governance.PromptGovernanceRuntimeCacheInvalidationService;
import io.contexa.contexaiam.admin.promptquality.inspection.JdbcPromptInspectionQueries;
import io.contexa.contexaiam.admin.promptquality.inspection.SealedDecisionReplays;
import io.contexa.contexaiam.admin.promptquality.measure.PromptQualityMeasurements;
import io.contexa.contexaiam.admin.promptquality.measure.PromptQualityRunLine;
import io.contexa.contexaiam.admin.promptquality.measure.QualityMeasureLock;
import io.contexa.contexaiam.admin.promptquality.measure.QualityModelSetting;
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
import org.springframework.boot.context.properties.EnableConfigurationProperties;
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
 * line of the trials, and one server at a time runs them under the lock of the scheduled work of Contexa.
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
                                                     ObjectProvider<SealedDecisionReplays> replays) {
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
}
