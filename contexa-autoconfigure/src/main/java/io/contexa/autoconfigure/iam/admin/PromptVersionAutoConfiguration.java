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
import io.contexa.autoconfigure.core.CoreDataAutoConfiguration;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptDocument;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate;
import io.contexa.contexacore.config.TieredLLMProperties;
import io.contexa.contexacore.monitoring.zerotrust.ZeroTrustCoverageCounter;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceDescriptor;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceDescriptorResolver;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleSelector;
import io.contexa.contexacore.std.components.prompt.quality.QualityGateSource;
import io.contexa.contexacore.std.components.prompt.version.ProductPromptRelease;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionCatalog;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionInUse;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionStore;
import io.contexa.contexacore.std.components.prompt.version.VersionedPrompt;
import io.contexa.contexacore.std.components.prompt.version.VersionedPrompts;
import io.contexa.contexacore.std.rag.QueryTransformPrompt;
import io.contexa.contexacore.std.llm.client.ProviderAwareChatOptionsFactory;
import io.contexa.contexacore.std.llm.model.DynamicModelRegistry;
import io.contexa.contexacore.std.llm.model.ModelDescriptor;
import io.contexa.contexaiam.admin.promptquality.governance.JdbcPromptGovernanceDescriptorResolver;
import io.contexa.contexaiam.aiam.components.prompt.ConditionTemplatePromptTemplate;
import io.contexa.contexaiam.aiam.components.prompt.PolicyGenerationStreamingTemplate;
import io.contexa.contexaiam.aiam.components.prompt.PolicyGenerationTemplate;
import io.contexa.contexaiam.aiam.components.prompt.ResourceNamingTemplate;
import io.contexa.contexaiam.admin.promptquality.version.AuditLogPromptVersionAudit;
import io.contexa.contexaiam.admin.promptquality.version.JdbcPromptVersionCatalog;
import io.contexa.contexaiam.admin.promptquality.version.JdbcPromptVersionStore;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionAudit;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionFolderScanner;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionLengthLimits;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionResolver;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionService;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionStartup;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.TaskScheduler;

import java.nio.file.Path;
import java.time.Clock;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The versions of the prompts in the database (plan 3.3, 3.4, 3.7, 3.8): the version service with the product documents
 * of the build and the registry row each version gets, the store the engine finds a version in (the database first,
 * the product documents behind it, plan 3.8 11), the resolver that chooses the version of every decision (the label of
 * the screen, the setting, the newest Contexa version, plan 3.4), the audit log of what is done to a version, the start
 * of a node (the product versions registered, the rows of earlier bundles retired) and, with
 * {@code contexa.prompt.versions.directory}, the document folder read at start and every minute.
 *
 * <p>Ordered before the prompt governance: the resolver is the decision's {@link PromptBundleSelector} in every
 * installation with the console's database, so the registry selector of
 * {@code contexa.security.tiered.prompt-bundle.selector=registry} stands aside and the resolver reads the registry
 * itself. With prompt governance turned off there is no registry and the resolver reads the setting and the newest
 * version. Without the console's database none of this is registered and the engine runs the configured name against
 * the product documents.
 */
@AutoConfiguration(after = CoreDataAutoConfiguration.class, before = PromptGovernanceAutoConfiguration.class)
@ConditionalOnBean(name = "contexaJdbcTemplate")
public class PromptVersionAutoConfiguration {

    /** The setting of the document folder (plan 3.8, 8); no folder is read without it. */
    static final String FOLDER_PROPERTY = "contexa.prompt.versions.directory";

    /** The context window a model's capabilities carry when nothing declared one. */
    static final int UNDECLARED_CONTEXT_WINDOW = ModelDescriptor.ModelCapabilities.builder().build().getContextWindow();

    /** Plan 3.7: the console's audit log, else no record (a host without the audit facade). */
    @Bean(name = "contexaPromptVersionAudit")
    @ConditionalOnMissingBean(PromptVersionAudit.class)
    public PromptVersionAudit promptVersionAudit(ObjectProvider<CentralAuditFacade> centralAuditFacade) {
        CentralAuditFacade facade = centralAuditFacade.getIfAvailable();
        return facade != null ? new AuditLogPromptVersionAudit(facade) : PromptVersionAudit.none();
    }

    /**
     * The versions of the database, with the product documents of the security decision this build ships and the
     * registry row of its versions, named as the template that runs them is.
     */
    @Bean(name = "contexaPromptVersionService")
    @ConditionalOnMissingBean
    public PromptVersionService promptVersionService(@Qualifier("contexaJdbcTemplate") JdbcTemplate jdbcTemplate,
                                                     PromptVersionAudit contexaPromptVersionAudit,
                                                     VersionedPrompts contexaVersionedPrompts) {
        Map<String, PromptVersionService.RegistryTarget> targets = new LinkedHashMap<>();
        targets.put(SecurityDecisionPromptDocument.PROMPT,
                target(SecurityDecisionStandardPromptTemplate.SECURITY_DECISION_PROMPT_GOVERNANCE));
        List<ProductPromptRelease> products = new ArrayList<>(SecurityDecisionPromptDocument.productReleases());
        for (VersionedPrompt prompt : contexaVersionedPrompts.prompts()) {
            targets.put(prompt.prompt(), target(prompt.registryDescriptor()));
            products.addAll(prompt.productReleases());
        }
        return new PromptVersionService(() -> jdbcTemplate, products, targets, contexaPromptVersionAudit,
                Clock.systemUTC());
    }

    private static PromptVersionService.RegistryTarget target(PromptGovernanceDescriptor descriptor) {
        return new PromptVersionService.RegistryTarget(descriptor.templateKey(), descriptor.contractVersion(),
                descriptor.templateClassName(), descriptor.owner());
    }

    /**
     * Plan 3.11: the prompts other than the security decision that run from their versions, after it in the version
     * screens: the four IAM templates and the three query rewrites of the RAG searches.
     */
    @Bean(name = "contexaVersionedPrompts")
    @ConditionalOnMissingBean
    public VersionedPrompts versionedPrompts() {
        List<VersionedPrompt> prompts = new ArrayList<>(List.of(new PolicyGenerationTemplate(),
                new PolicyGenerationStreamingTemplate(), new ConditionTemplatePromptTemplate(),
                new ResourceNamingTemplate()));
        prompts.addAll(QueryTransformPrompt.ALL);
        return new VersionedPrompts(prompts);
    }

    /**
     * Plan 3.9: the versions of the database as the release gate, the rollback and the replay of a sealed decision read
     * them; the version a scope decides with is the one the decision's selector chooses.
     */
    @Bean(name = "contexaPromptVersionCatalog")
    @ConditionalOnMissingBean(PromptVersionCatalog.class)
    public PromptVersionCatalog promptVersionCatalog(PromptVersionService contexaPromptVersionService,
                                                     @Qualifier("contexaJdbcTemplate") JdbcTemplate jdbcTemplate,
                                                     ObjectProvider<PromptBundleSelector> promptBundleSelector) {
        return new JdbcPromptVersionCatalog(contexaPromptVersionService, () -> jdbcTemplate,
                promptBundleSelector::getIfAvailable);
    }

    /** Plan 3.8 (2, 7, 11): the store the engine reads a version from, the product documents behind the database. */
    @Bean(name = "contexaPromptVersionStore")
    @ConditionalOnMissingBean(PromptVersionStore.class)
    public PromptVersionStore promptVersionStore(PromptVersionService contexaPromptVersionService,
                                                 VersionedPrompts contexaVersionedPrompts) {
        PromptVersionStore decision = SecurityDecisionPromptDocument.productStore();
        PromptVersionStore others = contexaVersionedPrompts.productStore();
        return new JdbcPromptVersionStore(contexaPromptVersionService,
                (prompt, version) -> decision.find(prompt, version).or(() -> others.find(prompt, version)));
    }

    /**
     * Plan 3.11: the version each call of a prompt other than the security decision draws, from the resolver and the
     * store; they are looked up at the first call, so the templates can be made before them.
     */
    @Bean(name = "contexaPromptVersionInUse")
    @ConditionalOnMissingBean
    public PromptVersionInUse promptVersionInUse(ObjectProvider<PromptBundleSelector> selector,
                                                 ObjectProvider<PromptVersionStore> store) {
        return new PromptVersionInUse(selector::getIfAvailable, store::getIfAvailable);
    }

    /**
     * Plan 3.4: the version of every decision, from the label of the request's scope (else the platform's), the setting
     * {@code contexa.security.tiered.prompt-bundle.active} read for each decision, and the newest Contexa version. The
     * registry is the one the descriptor resolver reads, so both share its cached releases and invalidation poll.
     */
    @Bean(name = "contexaPromptVersionResolver")
    @ConditionalOnMissingBean(PromptBundleSelector.class)
    public PromptVersionResolver promptVersionResolver(
            PromptVersionService contexaPromptVersionService,
            ObjectProvider<PromptGovernanceDescriptorResolver> promptGovernanceDescriptorResolver,
            ObjectProvider<TieredStrategyProperties> tieredStrategyProperties,
            @Qualifier("contexaJdbcTemplate") JdbcTemplate jdbcTemplate,
            @Qualifier("contexaObjectMapper") ObjectProvider<ObjectMapper> objectMapper,
            ObjectProvider<QualityGateSource> qualityGateSource) {
        PromptGovernanceDescriptorResolver descriptorResolver = promptGovernanceDescriptorResolver.getIfAvailable();
        PromptBundleSelector registry = null;
        if (descriptorResolver instanceof JdbcPromptGovernanceDescriptorResolver jdbcResolver) {
            registry = jdbcResolver.registrySelector();
        }
        else if (descriptorResolver != null) {
            registry = new JdbcPromptGovernanceDescriptorResolver(jdbcTemplate,
                    objectMapper.getIfAvailable(ObjectMapper::new)).registrySelector();
        }
        TieredStrategyProperties properties = tieredStrategyProperties.getIfAvailable(TieredStrategyProperties::new);
        PromptVersionResolver resolver = new PromptVersionResolver(registry, contexaPromptVersionService,
                () -> properties.getPromptBundle().getActive(), Clock.systemUTC());
        // Plan 3.4: a version that decides outside the release gate is checked once for a measurement taken here.
        resolver.setQualityGateSource(qualityGateSource::getIfAvailable);
        return resolver;
    }

    /**
     * Plan 3.5 (check 4): the context of the model that decides first, the answer and the longest recent input, each
     * recent decision measured with the version it ran (K70).
     */
    @Bean(name = "contexaPromptVersionLengthLimits")
    @ConditionalOnMissingBean
    public PromptVersionLengthLimits promptVersionLengthLimits(@Qualifier("contexaJdbcTemplate") JdbcTemplate jdbcTemplate,
                                                               ObjectProvider<TieredLLMProperties> llmProperties,
                                                               ObjectProvider<DynamicModelRegistry> models,
                                                               ObjectProvider<TieredStrategyProperties> strategy,
                                                               ObjectProvider<PromptVersionStore> store) {
        return new PromptVersionLengthLimits(() -> jdbcTemplate,
                () -> firstLayerModel(llmProperties, models).map(ModelDescriptor::getProvider).orElse(null),
                // K54: no setting declares a model's context window; the capabilities carry their builder's default,
                // which says nothing of the model, so the context is not known and nothing is refused for length.
                () -> firstLayerModel(llmProperties, models).map(ModelDescriptor::getCapabilities)
                        .map(ModelDescriptor.ModelCapabilities::getContextWindow)
                        .filter(window -> window != UNDECLARED_CONTEXT_WINDOW).orElse(null),
                ProviderAwareChatOptionsFactory::ollamaMaxContextLength,
                () -> {
                    TieredStrategyProperties properties = strategy.getIfAvailable();
                    return properties == null ? 0 : Math.max(properties.getLayer1().getMaxOutputTokens(),
                            properties.getLayer2().getMaxOutputTokens());
                },
                (prompt, version) -> {
                    PromptVersionStore versions = store.getIfAvailable();
                    return versions != null ? versions.find(prompt, version) : Optional.empty();
                },
                SecurityDecisionPromptDocument.product());
    }

    private static Optional<ModelDescriptor> firstLayerModel(ObjectProvider<TieredLLMProperties> llmProperties,
                                                             ObjectProvider<DynamicModelRegistry> models) {
        TieredLLMProperties properties = llmProperties.getIfAvailable();
        DynamicModelRegistry registry = models.getIfAvailable();
        if (properties == null || registry == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(registry.getDescriptor(properties.getModelNameForTier(1)));
    }

    /** Plan 3.8 (8): the document folder of this node, when the setting names one. */
    @Bean(name = "contexaPromptVersionFolderScanner")
    @ConditionalOnMissingBean
    @ConditionalOnProperty(name = FOLDER_PROPERTY)
    public PromptVersionFolderScanner promptVersionFolderScanner(
            @Qualifier("contexaJdbcTemplate") JdbcTemplate jdbcTemplate,
            PromptVersionService contexaPromptVersionService, Environment environment,
            ObjectProvider<PromptVersionLengthLimits> limits) {
        // A document of the folder is checked against the length limit as a version saved on the screen is.
        return new PromptVersionFolderScanner(() -> jdbcTemplate, contexaPromptVersionService,
                Path.of(environment.getRequiredProperty(FOLDER_PROPERTY).trim()), ZeroTrustCoverageCounter.hostNodeId(),
                () -> {
                    PromptVersionLengthLimits limit = limits.getIfAvailable();
                    return limit != null ? limit.get() : null;
                });
    }

    /**
     * The start of a node: the product versions registered, the rows of earlier bundles retired, the folder read now
     * and every minute. Last among the runners, after the registry's own start registered the build's bundle row it
     * retires.
     */
    @Bean(name = "contexaPromptVersionStartupRunner")
    @ConditionalOnMissingBean(name = "contexaPromptVersionStartupRunner")
    @Order(Ordered.LOWEST_PRECEDENCE)
    public ApplicationRunner promptVersionStartupRunner(
            PromptVersionService contexaPromptVersionService,
            ObjectProvider<PromptVersionFolderScanner> promptVersionFolderScanner,
            @Qualifier("contexaTaskScheduler") ObjectProvider<TaskScheduler> scheduler) {
        PromptVersionStartup startup = new PromptVersionStartup(contexaPromptVersionService,
                promptVersionFolderScanner.getIfAvailable());
        return args -> startup.start(scheduler.getIfAvailable());
    }
}
