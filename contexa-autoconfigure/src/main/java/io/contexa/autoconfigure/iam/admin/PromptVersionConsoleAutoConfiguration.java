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
import io.contexa.contexacore.std.components.prompt.version.VersionedPrompts;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleSelector;
import io.contexa.contexacore.std.components.prompt.governance.PromptGovernanceReleaseGateService;
import io.contexa.contexaiam.admin.promptquality.governance.JdbcPromptReleaseQueryService;
import io.contexa.contexaiam.admin.promptquality.governance.PromptBundleRollbackService;
import io.contexa.contexaiam.admin.promptquality.governance.PromptGovernanceRuntimeCacheInvalidationService;
import io.contexa.contexaiam.admin.promptquality.inspection.JdbcPromptInspectionQueries;
import io.contexa.contexaiam.admin.promptquality.inspection.SealedDecisionReplays;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionAudit;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsole;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleController;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionFolderScanner;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionLengthLimits;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionService;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionTrials;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleService;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;
import org.springframework.jdbc.core.JdbcTemplate;

import java.time.Clock;
import java.util.concurrent.Executors;

/**
 * The prompt version screens (plan 3.10, 6-5, 6-6): the console that composes what they show, the trials that decide
 * sealed decisions again with two versions, the length limit of the checks before saving, and the controller of the
 * screens and their API. They stand on the versions of the database: without the version service there are no screens.
 * The length limit of the checks is the version service's (PromptVersionAutoConfiguration).
 */
@AutoConfiguration(after = {PromptVersionAutoConfiguration.class, PromptGovernanceAutoConfiguration.class,
        PromptInspectionAutoConfiguration.class, IamAdminMonitoringAutoConfiguration.class})
@ConditionalOnProperty(prefix = "contexa.prompt.governance", name = "enabled", havingValue = "true", matchIfMissing = true)
public class PromptVersionConsoleAutoConfiguration {

    /** Plan 6-5: the trials, one at a time on a thread of their own; a trial a stop left unfinished is marked failed. */
    @Bean(name = "contexaPromptVersionTrials", destroyMethod = "close")
    @ConditionalOnMissingBean
    @ConditionalOnBean({PromptVersionService.class, SealedDecisionReplays.class})
    public PromptVersionTrials promptVersionTrials(@Qualifier("contexaJdbcTemplate") JdbcTemplate jdbcTemplate,
                                                   PromptVersionService versions, SealedDecisionReplays replays,
                                                   ObjectProvider<PromptVersionAudit> audit) {
        PromptVersionTrials trials = new PromptVersionTrials(() -> jdbcTemplate, versions,
                (actor, packageId, version) -> replays.replayPackage(actor, packageId,
                        new SealedDecisionReplays.ReplayRequest(version, null, null, null))
                        .map(replayed -> PromptVersionTrials.replayed(replayed.result())),
                Executors.newSingleThreadExecutor(work -> {
                    Thread thread = new Thread(work, "contexa-prompt-version-trial");
                    thread.setDaemon(true);
                    return thread;
                }),
                audit.getIfAvailable(PromptVersionAudit::none), Clock.systemUTC());
        trials.closeInterrupted();
        return trials;
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
                                                     ObjectProvider<VersionedPrompts> versionedPrompts) {
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
