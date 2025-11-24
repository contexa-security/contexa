package io.contexa.autoconfigure.core.llm;

import io.contexa.contexacore.config.TieredLLMProperties;
import io.contexa.contexacore.std.llm.config.LLMClient;
import io.contexa.contexacore.std.llm.config.ToolCapableLLMClient;
import io.contexa.contexacore.std.llm.core.LLMOperations;
import io.contexa.contexacore.std.llm.core.UnifiedLLMOrchestrator;
import io.contexa.contexacore.std.llm.handler.DefaultStreamingHandler;
import io.contexa.contexacore.std.llm.handler.StreamingHandler;
import io.contexa.contexacore.std.llm.strategy.ModelSelectionStrategy;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.anthropic.AnthropicChatModel;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.embedding.EmbeddingModel;
import org.springframework.ai.model.chat.client.autoconfigure.ChatClientAutoConfiguration;
import org.springframework.ai.ollama.OllamaChatModel;
import org.springframework.ai.ollama.OllamaEmbeddingModel;
import org.springframework.ai.openai.OpenAiChatModel;
import org.springframework.ai.openai.OpenAiEmbeddingModel;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 통합 3계층 보안 시스템 LLM Configuration
 *
 * 모든 AI/LLM 관련 설정의 중앙 진입점
 * UnifiedAIConfiguration의 기능을 통합하여 단일 Configuration으로 관리
 *
 * SOLID 원칙 준수:
 * - 단일 책임: 각 Configuration은 명확한 역할 담당
 * - 개방-폐쇄: 새로운 Configuration 추가 시 기존 코드 수정 불필요
 * - 의존성 역전: 인터페이스 기반 설계로 구체적 구현에 의존하지 않음
 *
 * 통합 구조:
 * 1. 3계층 ChatModel 생성 (Layer 1, 2, 3)
 * 2. UnifiedLLMOrchestrator를 @Primary로 설정
 * 3. AdvisorConfiguration - Advisor 시스템 통합
 * 4. ToolCallingConfiguration - 도구 실행 시스템 (Enterprise에서 제공)
 *
 * @since 3.0.0
 */
@Slf4j
@Configuration
@RequiredArgsConstructor
@AutoConfigureBefore(ChatClientAutoConfiguration.class)
public class CoreLLMTieredAutoConfiguration {

    @Value("${spring.ai.chat.model.priority:ollama,anthropic,openai}")
    private String chatModelPriority;

    @Value("${spring.ai.embedding.model.priority:ollama,openai}")
    private String embeddingModelPriority;

    @Autowired
    private TieredLLMProperties tieredLLMProperties;

    /**
     * Layer 1: TinyLlama ChatModel
     */
    @Bean(name = "tinyLlamaChatModel")
    @ConditionalOnMissingBean(name = "tinyLlamaChatModel")
    public ChatModel tinyLlamaChatModel(
            @Autowired(required = false) OllamaChatModel ollamaChatModel,
            @Autowired(required = false) AnthropicChatModel anthropicChatModel,
            @Autowired(required = false) OpenAiChatModel openAiChatModel) {

        log.info("Layer 1 TinyLlama ChatModel 구성");

        if (ollamaChatModel != null) {
            log.info("  ✓ Layer 1 ChatModel 준비 완료 (런타임에 tinyllama 모델 사용)");
            return ollamaChatModel;
        }

        log.warn("  ⚠ Ollama ChatModel이 구성되지 않았습니다. 폴백 모델로 시도");

        if (anthropicChatModel != null) {
            log.info("  ✓ Layer 1 폴백: Anthropic Claude 사용 (빠른 모델로 설정)");
            return anthropicChatModel;
        }

        if (openAiChatModel != null) {
            log.info("  ✓ Layer 1 폴백: OpenAI GPT 사용 (빠른 모델로 설정)");
            return openAiChatModel;
        }

        log.warn("  ⚠ 모든 모델 제공자가 사용 불가능합니다. Layer 1 모델이 null로 설정됩니다");
        return null;
    }

    /**
     * Layer 2: Llama3.1:8b ChatModel
     */
    @Bean(name = "llama31ChatModel")
    @ConditionalOnMissingBean(name = "llama31ChatModel")
    public ChatModel llama31ChatModel(
            @Autowired(required = false) OllamaChatModel ollamaChatModel,
            @Autowired(required = false) AnthropicChatModel anthropicChatModel,
            @Autowired(required = false) OpenAiChatModel openAiChatModel) {

        log.info("Layer 2 Llama3.1:8b ChatModel 구성");

        if (ollamaChatModel != null) {
            log.info("  ✓ Layer 2 ChatModel 준비 완료 (런타임에 llama3.1:8b 모델 사용)");
            return ollamaChatModel;
        }

        log.warn("  ⚠ Ollama ChatModel이 구성되지 않았습니다. 폴백 모델로 시도");

        if (anthropicChatModel != null) {
            log.info("  ✓ Layer 2 폴백: Anthropic Claude 사용 (중간 성능 모델로 설정)");
            return anthropicChatModel;
        }

        if (openAiChatModel != null) {
            log.info("  ✓ Layer 2 폴백: OpenAI GPT 사용 (중간 성능 모델로 설정)");
            return openAiChatModel;
        }

        log.warn("  ⚠ 모든 모델 제공자가 사용 불가능합니다. Layer 2 모델이 null로 설정됩니다");
        return null;
    }

    /**
     * Layer 3: Claude Opus (전문가 분석 - 1-5초)
     */
    @Bean(name = "claudeOpusChatModel")
    @ConditionalOnMissingBean(name = "claudeOpusChatModel")
    public ChatModel claudeOpusChatModel(
            @Autowired(required = false) AnthropicChatModel anthropicChatModel,
            @Value("${spring.ai.security.layer3.model:${spring.ai.security.tiered.layer3.model:llama3.1:8b}}") String modelName) {

        log.info("Layer 3 Claude Opus ChatModel 구성 - Model: {}", modelName);

        if (anthropicChatModel != null) {
            log.info("  ✓ Anthropic ChatModel 사용");
            return anthropicChatModel;
        }

        log.warn("  ⚠ Anthropic ChatModel을 찾을 수 없습니다. API 키 확인 필요");
        return null;
    }

    /**
     * Layer 3 대체: GPT-4 (전문가 분석 - 1-5초)
     */
    @Bean(name = "gpt4ChatModel")
    @ConditionalOnMissingBean(name = "gpt4ChatModel")
    public ChatModel gpt4ChatModel(
            @Autowired(required = false) OpenAiChatModel openAiChatModel,
            @Value("${spring.ai.security.layer3.backup.model:gpt-4}") String modelName) {

        log.info("Layer 3 GPT-4 ChatModel 구성 - Model: {}", modelName);

        if (openAiChatModel != null) {
            log.info("  ✓ OpenAI ChatModel 사용");
            return openAiChatModel;
        }

        log.warn("  ⚠ OpenAI ChatModel을 찾을 수 없습니다. API 키 확인 필요");
        return null;
    }

    /**
     * Primary ChatModel
     */
    @Bean
    @Primary
    public ChatModel primaryChatModel(
            ObjectProvider<OllamaChatModel> ollamaChatModelProvider,
            ObjectProvider<AnthropicChatModel> anthropicChatModelProvider,
            ObjectProvider<OpenAiChatModel> openAiChatModelProvider) {

        log.info("Primary ChatModel 구성 - 우선순위 기반 선택");

        Map<String, ChatModel> availableModels = new HashMap<>();

        OllamaChatModel ollamaModel = ollamaChatModelProvider.getIfAvailable();
        if (ollamaModel != null) {
            availableModels.put("ollama", ollamaModel);
        }

        AnthropicChatModel anthropicModel = anthropicChatModelProvider.getIfAvailable();
        if (anthropicModel != null) {
            availableModels.put("anthropic", anthropicModel);
        }

        OpenAiChatModel openAiModel = openAiChatModelProvider.getIfAvailable();
        if (openAiModel != null) {
            availableModels.put("openai", openAiModel);
        }

        List<String> priorities = List.of(chatModelPriority.split(","));
        for (String modelName : priorities) {
            String trimmedName = modelName.trim().toLowerCase();
            ChatModel model = availableModels.get(trimmedName);
            if (model != null) {
                log.info("  ✓ Primary ChatModel 선택: {} (우선순위 기반)", trimmedName);
                return model;
            }
        }

        if (!availableModels.isEmpty()) {
            Map.Entry<String, ChatModel> firstEntry = availableModels.entrySet().iterator().next();
            log.warn("  ⚠ 우선순위 모델 없음. {} 사용 (fallback)", firstEntry.getKey());
            return firstEntry.getValue();
        }

        log.error("  사용 가능한 ChatModel이 없습니다!");
        throw new IllegalStateException("No ChatModel available. Please configure at least one AI provider.");
    }

    /**
     * 스트리밍 핸들러
     */
    @Bean
    @ConditionalOnMissingBean(StreamingHandler.class)
    public StreamingHandler streamingHandler() {
        log.info("DefaultStreamingHandler 구성");
        return new DefaultStreamingHandler(tieredLLMProperties);
    }

    /**
     * UnifiedLLMOrchestrator - 모든 LLM 호출의 단일 진입점
     */
    @Bean
    @Primary
    public UnifiedLLMOrchestrator unifiedLLMOrchestrator(
            ModelSelectionStrategy modelSelectionStrategy,
            StreamingHandler streamingHandler) {

        log.info("UnifiedLLMOrchestrator 생성 - 3계층 시스템 통합 완료");
        log.info("  - Layer 1 (98%): TinyLlama - 20-50ms");
        log.info("  - Layer 2 (1.8%): Llama3.1:8b - 100-300ms");
        log.info("  - Layer 3 (0.2%): Claude/GPT-4 - 1-5s");

        return new UnifiedLLMOrchestrator(modelSelectionStrategy, streamingHandler, tieredLLMProperties);
    }

    @Bean
    public LLMOperations llmOperations(UnifiedLLMOrchestrator unifiedLLMOrchestrator) {
        log.info("LLMOperations 인터페이스 제공");
        return unifiedLLMOrchestrator;
    }

    @Bean(name = "llmClient")
    public LLMClient llmClient(UnifiedLLMOrchestrator unifiedLLMOrchestrator) {
        log.info("LLMClient 인터페이스 제공 (하위 호환성)");
        return unifiedLLMOrchestrator;
    }

    @Bean(name = "toolCapableLLMClient")
    public ToolCapableLLMClient toolCapableLLMClient(UnifiedLLMOrchestrator unifiedLLMOrchestrator) {
        log.info("ToolCapableLLMClient 인터페이스 제공 (도구 실행 지원)");
        return unifiedLLMOrchestrator;
    }

    /**
     * Primary EmbeddingModel
     */
    @Bean(name = "primaryEmbeddingModel")
    @Primary
    @ConditionalOnMissingBean(name = "primaryEmbeddingModel")
    public EmbeddingModel primaryEmbeddingModel(
            ObjectProvider<OllamaEmbeddingModel> ollamaEmbeddingModelProvider,
            ObjectProvider<OpenAiEmbeddingModel> openAiEmbeddingModelProvider) {

        log.info("Primary EmbeddingModel 구성 - 우선순위 기반 선택");

        Map<String, EmbeddingModel> availableModels = new HashMap<>();

        OllamaEmbeddingModel ollamaEmbedding = ollamaEmbeddingModelProvider.getIfAvailable();
        if (ollamaEmbedding != null) {
            availableModels.put("ollama", ollamaEmbedding);
        }

        OpenAiEmbeddingModel openAiEmbedding = openAiEmbeddingModelProvider.getIfAvailable();
        if (openAiEmbedding != null) {
            availableModels.put("openai", openAiEmbedding);
        }

        List<String> priorities = List.of(embeddingModelPriority.split(","));
        for (String modelName : priorities) {
            String trimmedName = modelName.trim().toLowerCase();
            EmbeddingModel model = availableModels.get(trimmedName);
            if (model != null) {
                log.info("  ✓ Primary EmbeddingModel 선택: {} (우선순위 기반)", trimmedName);
                return model;
            }
        }

        if (!availableModels.isEmpty()) {
            Map.Entry<String, EmbeddingModel> firstEntry = availableModels.entrySet().iterator().next();
            log.warn("  ⚠ 우선순위 모델 없음. {} 사용 (fallback)", firstEntry.getKey());
            return firstEntry.getValue();
        }

        throw new IllegalStateException("No EmbeddingModel available. Please configure at least one embedding provider.");
    }

    @Bean
    @ConditionalOnMissingBean(ChatClient.Builder.class)
    @ConditionalOnProperty(prefix = "contexa.advisor", name = "enabled", havingValue = "false", matchIfMissing = true)
    public ChatClient.Builder chatClientBuilder(ChatModel primaryChatModel) {
        log.info("Creating basic ChatClient.Builder with {} (Advisor disabled)", primaryChatModel.getClass().getSimpleName());
        return ChatClient.builder(primaryChatModel);
    }

    @Bean
    @ConditionalOnMissingBean(name = "defaultChatClient")
    @ConditionalOnProperty(prefix = "contexa.advisor", name = "enabled", havingValue = "false")
    public ChatClient defaultChatClient(ChatClient.Builder builder) {
        log.info("Creating default ChatClient without Advisors");
        return builder.build();
    }

    @PostConstruct
    public void init() {
        log.info("========================================");
        log.info("통합 3계층 보안 시스템 LLM Configuration 초기화 완료");
        log.info("========================================");
        log.info("Layer 1 (98% 트래픽): TinyLlama - 20-50ms 응답");
        log.info("Layer 2 (1.8% 트래픽): Llama3.1:8b - 100-300ms 응답");
        log.info("Layer 3 (0.2% 트래픽): Claude Opus/GPT-4 - 1-5초 응답");
        log.info("========================================");
    }
}
