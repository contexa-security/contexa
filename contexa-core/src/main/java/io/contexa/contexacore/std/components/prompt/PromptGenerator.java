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
package io.contexa.contexacore.std.components.prompt;

import io.contexa.contexacommon.domain.PromptTemplate;
import io.contexa.contexacommon.domain.TemplateType;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.messages.SystemMessage;
import org.springframework.ai.chat.messages.UserMessage;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
public class PromptGenerator {

    private static final Map<String, PromptTemplate> promptTemplates = new ConcurrentHashMap<>();
    private final List<PromptTemplate> templateBeans;
    private final LLMViewComposer llmViewComposer;
    private final TieredStrategyProperties tieredStrategyProperties;

    @Autowired
    public PromptGenerator(List<PromptTemplate> templateBeans) {
        this(templateBeans, null);
    }

    public PromptGenerator(List<PromptTemplate> templateBeans, LLMViewComposer llmViewComposer) {
        this(templateBeans, llmViewComposer, null);
    }

    public PromptGenerator(
            List<PromptTemplate> templateBeans,
            LLMViewComposer llmViewComposer,
            TieredStrategyProperties tieredStrategyProperties) {
        this.templateBeans = templateBeans;
        this.llmViewComposer = llmViewComposer != null ? llmViewComposer : new SafePromptNormalizationLLMViewComposer();
        this.tieredStrategyProperties = tieredStrategyProperties;
    }

    @PostConstruct
    private void autoRegisterTemplates() {
        for (PromptTemplate template : templateBeans) {
            registerTemplateFromBean(template);
        }
    }

    private void registerTemplateFromBean(PromptTemplate template) {
        promptTemplates.put(template.getSupportedType().name(), template);
    }

    public PromptGenerationResult generatePrompt(AIRequest<? extends DomainContext> request,
                                                 String contextInfo,
                                                 String systemMetadata) {

        String templateKey = determineTemplateKey(request);
        PromptTemplate template = promptTemplates.get(templateKey);
        String rawSystemPrompt = template.generateSystemPrompt(request, systemMetadata);
        String rawUserPrompt = template.generateUserPrompt(request, contextInfo);
        PromptBudgetProfile effectiveBudgetProfile = resolveBudgetProfile(request, template, rawSystemPrompt, rawUserPrompt);
        String modelHint = PromptGovernanceSupport.resolveRequestedModelHint(request);
        PromptViewComposition promptViewComposition = llmViewComposer.compose(
                rawSystemPrompt,
                rawUserPrompt,
                effectiveBudgetProfile,
                modelHint);
        validatePromptViewComposition(rawSystemPrompt, rawUserPrompt, promptViewComposition);
        String systemPrompt = promptViewComposition.llmSystemPrompt();
        String userPrompt = promptViewComposition.llmUserPrompt();

        PromptExecutionMetadata promptExecutionMetadata =
                buildPromptExecutionMetadata(request, templateKey, template, promptViewComposition);
        Map<String, Object> metadata = new LinkedHashMap<>(promptExecutionMetadata.toMetadataMap());

        SystemMessage systemMessage = SystemMessage.builder().text(systemPrompt).metadata(metadata).build();
        UserMessage userMessage = UserMessage.builder().text(userPrompt).metadata(metadata).build();
        Prompt prompt = new Prompt(List.of(systemMessage, userMessage));

        return new PromptGenerationResult(
                prompt,
                systemPrompt,
                userPrompt,
                promptViewComposition.rawSystemPrompt(),
                promptViewComposition.rawUserPrompt(),
                metadata,
                promptExecutionMetadata);
    }

    public void registerTemplate(String key, PromptTemplate template) {
        promptTemplates.put(key, template);
    }

    public Class<?> getAIGenerationType(AIRequest<? extends DomainContext> request) {
        String templateKey = determineTemplateKey(request);
        PromptTemplate template = promptTemplates.get(templateKey);

        if (template == null) {
            template = promptTemplates.get("default");
        }

        if (template != null) {
            return template.getAIGenerationType();
        }

        return null;
    }

    public static String determineTemplateKey(AIRequest<? extends DomainContext> request) {
        TemplateType templateType = request.getPromptTemplate();

        if (promptTemplates.containsKey(templateType.name())) {
            return templateType.name();
        }
        log.error("Template matching failed. Available keys: {}", promptTemplates.keySet());
        throw new IllegalArgumentException("Template matching failed");
    }

    private PromptExecutionMetadata buildPromptExecutionMetadata(
            AIRequest<? extends DomainContext> request,
            String templateKey,
            PromptTemplate template,
            PromptViewComposition promptViewComposition) {
        if (template instanceof GovernedPromptTemplate governedPromptTemplate) {
            return governedPromptTemplate.buildPromptExecutionMetadata(request, promptViewComposition);
        }
        PromptGovernanceDescriptor descriptor =
                PromptGovernanceSupport.buildDefaultDescriptor(templateKey, template.getClass());
        return PromptGovernanceSupport.buildExecutionMetadata(
                descriptor,
                resolveBudgetProfile(request, template,
                        promptViewComposition.rawSystemPrompt(),
                        promptViewComposition.rawUserPrompt()),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                PromptEvidenceCompleteness.SUFFICIENT,
                PromptGovernanceSupport.resolveRequestedModelHint(request),
                promptViewComposition.llmSystemPrompt(),
                promptViewComposition.llmUserPrompt(),
                promptViewComposition.rawSystemPrompt(),
                promptViewComposition.rawUserPrompt(),
                promptViewComposition.compressionLedger());
    }

    private PromptBudgetProfile resolveBudgetProfile(
            AIRequest<? extends DomainContext> request,
            PromptTemplate template,
            String systemPrompt,
            String userPrompt) {
        PromptBudgetProfile configuredLayer1Default = configuredLayer1DefaultBudgetProfile();
        if (request == null) {
            return configuredLayer1Default;
        }
        Object parameter = request.getParameter("promptBudgetProfile", Object.class);
        if (parameter instanceof PromptBudgetProfile profile) {
            return profile;
        }
        if (parameter instanceof String profileKey) {
            return PromptBudgetProfile.fromKey(profileKey, configuredLayer1Default);
        }
        if (template instanceof GovernedPromptTemplate governedPromptTemplate) {
            PromptExecutionMetadata metadata = governedPromptTemplate.buildPromptExecutionMetadata(request, systemPrompt, userPrompt);
            if (metadata != null && metadata.budgetProfile() != null) {
                return metadata.budgetProfile();
            }
        }
        return configuredLayer1Default;
    }

    private PromptBudgetProfile configuredLayer1DefaultBudgetProfile() {
        String configuredProfile = tieredStrategyProperties != null && tieredStrategyProperties.getLayer1() != null
                ? tieredStrategyProperties.getLayer1().getDefaultBudgetProfile()
                : null;
        return PromptBudgetProfile.fromKey(configuredProfile, PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT);
    }

    private void validatePromptViewComposition(
            String rawSystemPrompt,
            String rawUserPrompt,
            PromptViewComposition composition) {
        if (composition == null) {
            throw new IllegalStateException("Prompt view composer must return a composition.");
        }

        String expectedRawSystemPrompt = normalizeLineEndings(rawSystemPrompt);
        String expectedRawUserPrompt = normalizeLineEndings(rawUserPrompt);
        if (!Objects.equals(expectedRawSystemPrompt, normalizeLineEndings(composition.rawSystemPrompt()))
                || !Objects.equals(expectedRawUserPrompt, normalizeLineEndings(composition.rawUserPrompt()))) {
            throw new IllegalStateException("Prompt view composer must preserve the generated raw prompt text.");
        }

        PromptCompressionLedger ledger = composition.compressionLedger();
        boolean exactParity = Objects.equals(composition.rawSystemPrompt(), composition.llmSystemPrompt())
                && Objects.equals(composition.rawUserPrompt(), composition.llmUserPrompt());
        int expectedSavedCharacters = Math.max(
                0,
                composition.rawSystemPrompt().length()
                        + composition.rawUserPrompt().length()
                        - composition.llmSystemPrompt().length()
                        - composition.llmUserPrompt().length());
        boolean ledgerMatches = ledger.rawPromptParity() == exactParity
                && ledger.rawSystemPromptLength() == composition.rawSystemPrompt().length()
                && ledger.rawUserPromptLength() == composition.rawUserPrompt().length()
                && ledger.llmSystemPromptLength() == composition.llmSystemPrompt().length()
                && ledger.llmUserPromptLength() == composition.llmUserPrompt().length()
                && ledger.savedCharacters() == expectedSavedCharacters;
        if (!ledgerMatches) {
            throw new IllegalStateException("Prompt composition ledger does not match the raw and final prompt text.");
        }
    }

    private String normalizeLineEndings(String value) {
        return Objects.requireNonNullElse(value, "")
                .replace("\r\n", "\n")
                .replace('\r', '\n');
    }

}
