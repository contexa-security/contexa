package io.contexa.contexacore.std.llm.dynamic;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.stereotype.Service;

/**
 * AI 모델을 동적으로 선택하여 사용하는 예시
 */
@Slf4j
@RequiredArgsConstructor
public class AIModelUsage {

    private final AIModelManager aiModelManager;

    /**
     * 1. 특정 모델을 명시적으로 선택하여 사용
     */
    public void useSpecificModel() {
        // Claude를 사용하여 코드 생성
        try {
            ChatResponse response = aiModelManager.chat(
                    AIModelManager.AIModelType.ANTHROPIC,
                    "Write a Python function to calculate fibonacci numbers"
            );
            log.info("Claude response: {}", response.getResult().getOutput().getText());
        } catch (Exception e) {
            log.error("Claude not available, falling back to Ollama");

            // Ollama로 폴백
            ChatResponse response = aiModelManager.chat(
                    AIModelManager.AIModelType.OLLAMA,
                    "Write a Python function to calculate fibonacci numbers"
            );
            log.info("Ollama response: {}", response.getResult().getOutput().getText());
        }
    }

    /**
     * 2. 작업 유형에 따라 최적의 모델 자동 선택
     */
    public void useOptimalModelForTask() {
        // 코드 생성 작업 - Claude가 우선
        ChatResponse codeResponse = aiModelManager.chatWithBestModel(
                AIModelManager.TaskType.CODE_GENERATION,
                "Create a REST API endpoint for user authentication"
        );

        // 빠른 응답이 필요한 작업 - Ollama가 우선
        ChatResponse quickResponse = aiModelManager.chatWithBestModel(
                AIModelManager.TaskType.QUICK_RESPONSE,
                "What is the capital of France?"
        );

        // 창의적 글쓰기 - Claude 또는 OpenAI가 우선
        ChatResponse creativeResponse = aiModelManager.chatWithBestModel(
                AIModelManager.TaskType.CREATIVE_WRITING,
                "Write a short story about AI"
        );
    }

    /**
     * 3. 조건에 따른 동적 모델 선택
     */
    public void useModelBasedOnConditions(String prompt, boolean needHighQuality, boolean needFastResponse) {
        AIModelManager.AIModelType selectedModel;

        if (needHighQuality && !needFastResponse) {
            // 고품질이 중요하고 속도는 중요하지 않음 - Claude 사용
            selectedModel = AIModelManager.AIModelType.ANTHROPIC;
        } else if (needFastResponse) {
            // 빠른 응답이 중요 - Ollama 사용
            selectedModel = AIModelManager.AIModelType.OLLAMA;
        } else {
            // 균형잡힌 선택 - OpenAI 사용
            selectedModel = AIModelManager.AIModelType.OPENAI;
        }

        try {
            ChatResponse response = aiModelManager.chat(selectedModel, prompt);
            log.info("Response from {}: {}", selectedModel, response.getResult().getOutput().getText());
        } catch (Exception e) {
            log.error("Failed with {}, using fallback", selectedModel);
            ChatResponse response = aiModelManager.chatWithFastest(prompt);
            log.info("Fallback response: {}", response.getResult().getOutput().getText());
        }
    }

    /**
     * 4. 비용 최적화를 위한 계층적 모델 사용
     */
    public String costOptimizedChat(String prompt) {
        // 먼저 저렴한 모델로 시도
        try {
            // Step 1: Ollama (무료, 로컬)
            ChatResponse response = aiModelManager.chat(
                    AIModelManager.AIModelType.OLLAMA,
                    prompt
            );
            String result = response.getResult().getOutput().getText();

            // 응답 품질 검증 (예: 길이, 키워드 포함 여부 등)
            if (isQualityAcceptable(result)) {
                return result;
            }

            log.info("Ollama response quality not acceptable, escalating to OpenAI");
        } catch (Exception e) {
            log.warn("Ollama failed: {}", e.getMessage());
        }

        // Step 2: OpenAI (중간 비용)
        try {
            ChatResponse response = aiModelManager.chat(
                    AIModelManager.AIModelType.OPENAI,
                    prompt
            );
            return response.getResult().getOutput().getText();
        } catch (Exception e) {
            log.warn("OpenAI failed: {}", e.getMessage());
        }

        // Step 3: Claude (높은 비용, 최고 품질)
        ChatResponse response = aiModelManager.chat(
                AIModelManager.AIModelType.ANTHROPIC,
                prompt
        );
        return response.getResult().getOutput().getText();
    }

    /**
     * 5. 멀티 모델 앙상블 (여러 모델의 결과를 조합)
     */
    public String ensembleResponse(String prompt) {
        StringBuilder combinedResponse = new StringBuilder();

        // 모든 사용 가능한 모델로부터 응답 수집
        for (AIModelManager.AIModelType modelType : AIModelManager.AIModelType.values()) {
            try {
                ChatResponse response = aiModelManager.chat(modelType, prompt);
                combinedResponse.append("\n[").append(modelType.getDisplayName()).append("]:\n");
                combinedResponse.append(response.getResult().getOutput().getText());
                combinedResponse.append("\n---\n");
            } catch (Exception e) {
                log.debug("{} not available", modelType);
            }
        }

        return combinedResponse.toString();
    }

    private boolean isQualityAcceptable(String response) {
        // 실제 구현에서는 더 정교한 품질 검증 로직 필요
        return response != null && response.length() > 100;
    }
}