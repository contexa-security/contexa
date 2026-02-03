package io.contexa.contexacore.std.components.prompt;

import io.contexa.contexacommon.domain.PromptTemplate;
import io.contexa.contexacommon.domain.TemplateType;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacore.std.pipeline.streaming.StreamingProtocol;
import jakarta.annotation.PostConstruct;
import org.springframework.ai.chat.messages.SystemMessage;
import org.springframework.ai.chat.messages.UserMessage;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class PromptGenerator {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(PromptGenerator.class);

    private static final Map<String, PromptTemplate> promptTemplates = new ConcurrentHashMap<>();
    private final List<PromptTemplate> templateBeans;

    @Autowired
    public PromptGenerator(List<PromptTemplate> templateBeans) {
        this.templateBeans = templateBeans;
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
        String systemPrompt = template.generateSystemPrompt(request, systemMetadata);
        String userPrompt = template.generateUserPrompt(request, contextInfo);

        Map<String, Object> metadata = Map.of(
                "templateKey", templateKey,
                "systemPromptLength", systemPrompt.length(),
                "userPromptLength", userPrompt.length(),
                "generationTime", System.currentTimeMillis()
        );

        SystemMessage systemMessage = SystemMessage.builder().text(systemPrompt).metadata(metadata).build();
        UserMessage userMessage = UserMessage.builder().text(userPrompt).metadata(metadata).build();
        Prompt prompt = new Prompt(List.of(systemMessage, userMessage));

        return new PromptGenerationResult(prompt, systemPrompt, userPrompt, metadata);
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

    public static class PromptGenerationResult {
        private final Prompt prompt;
        private final String systemPrompt;
        private final String userPrompt;
        private final Map<String, Object> metadata;

        public PromptGenerationResult(Prompt prompt, String systemPrompt, String userPrompt, Map<String, Object> metadata) {
            this.prompt = prompt;
            this.systemPrompt = systemPrompt;
            this.userPrompt = userPrompt;
            this.metadata = metadata;
        }

        public Prompt getPrompt() {
            return prompt;
        }

        public String getSystemPrompt() {
            return systemPrompt;
        }

        public String getUserPrompt() {
            return userPrompt;
        }

        public Map<String, Object> getMetadata() {
            return metadata;
        }
    }
}