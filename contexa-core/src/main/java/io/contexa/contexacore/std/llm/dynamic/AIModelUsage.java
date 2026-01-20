package io.contexa.contexacore.std.llm.dynamic;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.stereotype.Service;


@Slf4j
@RequiredArgsConstructor
public class AIModelUsage {

    private final AIModelManager aiModelManager;

    
    public void useSpecificModel() {
        
        try {
            ChatResponse response = aiModelManager.chat(
                    AIModelManager.AIModelType.ANTHROPIC,
                    "Write a Python function to calculate fibonacci numbers"
            );
            log.info("Claude response: {}", response.getResult().getOutput().getText());
        } catch (Exception e) {
            log.error("Claude not available, falling back to Ollama");

            
            ChatResponse response = aiModelManager.chat(
                    AIModelManager.AIModelType.OLLAMA,
                    "Write a Python function to calculate fibonacci numbers"
            );
            log.info("Ollama response: {}", response.getResult().getOutput().getText());
        }
    }

    
    public void useOptimalModelForTask() {
        
        ChatResponse codeResponse = aiModelManager.chatWithBestModel(
                AIModelManager.TaskType.CODE_GENERATION,
                "Create a REST API endpoint for user authentication"
        );

        
        ChatResponse quickResponse = aiModelManager.chatWithBestModel(
                AIModelManager.TaskType.QUICK_RESPONSE,
                "What is the capital of France?"
        );

        
        ChatResponse creativeResponse = aiModelManager.chatWithBestModel(
                AIModelManager.TaskType.CREATIVE_WRITING,
                "Write a short story about AI"
        );
    }

    
    public void useModelBasedOnConditions(String prompt, boolean needHighQuality, boolean needFastResponse) {
        AIModelManager.AIModelType selectedModel;

        if (needHighQuality && !needFastResponse) {
            
            selectedModel = AIModelManager.AIModelType.ANTHROPIC;
        } else if (needFastResponse) {
            
            selectedModel = AIModelManager.AIModelType.OLLAMA;
        } else {
            
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

    
    public String costOptimizedChat(String prompt) {
        
        try {
            
            ChatResponse response = aiModelManager.chat(
                    AIModelManager.AIModelType.OLLAMA,
                    prompt
            );
            String result = response.getResult().getOutput().getText();

            
            if (isQualityAcceptable(result)) {
                return result;
            }

            log.info("Ollama response quality not acceptable, escalating to OpenAI");
        } catch (Exception e) {
            log.warn("Ollama failed: {}", e.getMessage());
        }

        
        try {
            ChatResponse response = aiModelManager.chat(
                    AIModelManager.AIModelType.OPENAI,
                    prompt
            );
            return response.getResult().getOutput().getText();
        } catch (Exception e) {
            log.warn("OpenAI failed: {}", e.getMessage());
        }

        
        ChatResponse response = aiModelManager.chat(
                AIModelManager.AIModelType.ANTHROPIC,
                prompt
        );
        return response.getResult().getOutput().getText();
    }

    
    public String ensembleResponse(String prompt) {
        StringBuilder combinedResponse = new StringBuilder();

        
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
        
        return response != null && response.length() > 100;
    }
}