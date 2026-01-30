package io.contexa.contexacore.std.components.prompt;

import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
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

        if (!promptTemplates.containsKey("default")) {
            promptTemplates.put("default", new DefaultIAMPolicyTemplate());
        }
    }

    private void registerTemplateFromBean(PromptTemplate template) {
        Class<?> templateClass = template.getClass();

        if (templateClass.isAnnotationPresent(PromptTemplateConfig.class)) {
            PromptTemplateConfig config = templateClass.getAnnotation(PromptTemplateConfig.class);

            promptTemplates.put(config.key(), template);

            for (String alias : config.aliases()) {
                promptTemplates.put(alias, template);
                            }
        } else {
            
            String className = templateClass.getSimpleName();
            String key = className.replace("Template", "").toLowerCase();
            promptTemplates.put(key, template);
                    }
    }

    public PromptGenerationResult generatePrompt(AIRequest<? extends DomainContext> request,
                                                 String contextInfo,
                                                 String systemMetadata) {

        String templateKey = determineTemplateKey(request);
        PromptTemplate template = promptTemplates.get(templateKey);

        if (template == null) {
            template = promptTemplates.get("default");
        }

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
        String promptTemplate = request.getPromptTemplate();
        String domainType = request.getContext().getDomainType();

        String specificKey = promptTemplate + "_" + domainType;
                if (promptTemplates.containsKey(specificKey)) {
                        return specificKey;
        }

                if (promptTemplates.containsKey(promptTemplate)) {
                        return promptTemplate;
        }

                if (promptTemplates.containsKey(domainType)) {
                        return domainType;
        }

        log.error("Template matching failed - using default. Available keys: {}", promptTemplates.keySet());
        return "default";
    }

    private static class DefaultIAMPolicyTemplate implements PromptTemplate {
        @Override
        public String generateSystemPrompt(AIRequest<? extends DomainContext> request, String systemMetadata) {
            return String.format("""
                당신은 IAM 정책 분석 AI '아비터'입니다. 
                
                임무: 자연어 요구사항을 분석하여 구체적인 정책 구성 요소로 변환
                
                시스템 정보:
                %s
                
                치명적 JSON 규칙 (위반 시 시스템 즉시 중단):
                1. JSON 내부에 // 또는 /* */ 주석 절대 금지 - 시스템 파싱 실패 원인
                2. JSON 내부에 설명이나 코멘트 텍스트 절대 금지
                3. conditions 필드에서 주석 사용 시 완전 파싱 실패
                4. 모든 키와 값은 순수 JSON 형식만 사용
                5. 각 필드는 한 번만 포함 (중복 절대 금지)
                6. 모든 ID는 반드시 숫자만 사용
                7. 문자열 값은 반드시 쌍따옴표로 감싸기
                8. 마지막 항목 뒤에 쉼표 절대 금지
                9. 빈 값은 빈 문자열("")이나 빈 배열([]) 사용
                
                특히 conditions 필드는 다음과 같이만 작성:
                "conditions": {"16": ["MONDAY", "TUESDAY", "WEDNESDAY", "THURSDAY", "FRIDAY"]}
                절대 이렇게 하지 마세요: "conditions": {"1": ["14", "16"]// 주석}
                
                JSON 파싱 오류 방지를 위한 추가 규칙:
                - 키는 반드시 쌍따옴표로 감싸기: "key"
                - 값도 반드시 적절한 타입으로: "string", 123, true, []
                - 객체나 배열이 비어있으면: {}, []
                - 특수문자는 이스케이프: \", \\, \n
                
                📤 필수 JSON 형식 (정확히 이 형식만 사용):
                
                ===JSON시작===
                {
                  "policyName": "정책이름",
                  "description": "정책설명", 
                  "roleIds": [2],
                  "permissionIds": [3],
                  "conditions": {"1": ["MONDAY", "TUESDAY", "WEDNESDAY", "THURSDAY", "FRIDAY"]},
                  "aiRiskAssessmentEnabled": false,
                  "requiredTrustScore": 0.7,
                  "customConditionSpel": "",
                  "effect": "ALLOW"
                }
                ===JSON끝===
                
                분석 과정이나 설명은 JSON 블록 앞에 작성하고, JSON은 완벽하게 파싱 가능한 형태로만 작성하세요.
                """, systemMetadata);
        }

        @Override
        public String generateUserPrompt(AIRequest<? extends DomainContext> request, String contextInfo) {
            String naturalLanguageQuery = extractQueryFromRequest(request);

            return String.format("""
                **자연어 요구사항:**
                "%s"
                
                **참고 컨텍스트:**
                %s
                
                위 요구사항을 분석하여 정책을 구성해주세요.
                """, naturalLanguageQuery, contextInfo);
        }
    }

    private static String extractQueryFromRequest(AIRequest<? extends DomainContext> request) {
        return request.getParameter("naturalLanguageQuery", String.class); 
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

        public Prompt getPrompt() { return prompt; }
        public String getSystemPrompt() { return systemPrompt; }
        public String getUserPrompt() { return userPrompt; }
        public Map<String, Object> getMetadata() { return metadata; }
    }
}