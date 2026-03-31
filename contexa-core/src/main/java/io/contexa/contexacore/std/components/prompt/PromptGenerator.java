package io.contexa.contexacore.std.components.prompt;

import io.contexa.contexacommon.domain.PromptTemplate;
import io.contexa.contexacommon.domain.TemplateType;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import jakarta.annotation.PostConstruct;
import org.springframework.ai.chat.messages.SystemMessage;
import org.springframework.ai.chat.messages.UserMessage;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class PromptGenerator {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(PromptGenerator.class);

    private static final Map<String, PromptTemplate> promptTemplates = new ConcurrentHashMap<>();
    private final List<PromptTemplate> templateBeans;
    private final LLMViewComposer llmViewComposer;

    @Autowired
    public PromptGenerator(List<PromptTemplate> templateBeans) {
        this(templateBeans, null);
    }

    public PromptGenerator(List<PromptTemplate> templateBeans, LLMViewComposer llmViewComposer) {
        this.templateBeans = templateBeans;
        this.llmViewComposer = llmViewComposer != null ? llmViewComposer : new SafePromptNormalizationLLMViewComposer();
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
        PromptViewComposition promptViewComposition = llmViewComposer.compose(
                rawSystemPrompt,
                rawUserPrompt,
                resolveBudgetProfile(request));
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
                resolveBudgetProfile(request),
                List.of(),
                List.of(),
                List.of(),
                PromptEvidenceCompleteness.SUFFICIENT,
                promptViewComposition.llmSystemPrompt(),
                promptViewComposition.llmUserPrompt(),
                promptViewComposition.rawSystemPrompt(),
                promptViewComposition.rawUserPrompt(),
                promptViewComposition.compressionLedger());
    }

    private PromptBudgetProfile resolveBudgetProfile(AIRequest<? extends DomainContext> request) {
        if (request == null) {
            return PromptBudgetProfile.CORTEX_L1_STANDARD;
        }
        Object parameter = request.getParameter("promptBudgetProfile", Object.class);
        if (parameter instanceof PromptBudgetProfile profile) {
            return profile;
        }
        if (parameter instanceof String profileKey) {
            return PromptBudgetProfile.fromKey(profileKey, PromptBudgetProfile.CORTEX_L1_STANDARD);
        }
        return PromptBudgetProfile.CORTEX_L1_STANDARD;
    }
}
