package io.contexa.contexacore.properties;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * LLM provider configuration properties.
 * Binds to spring.ai.* properties for each provider.
 */
@Getter
@Setter
@ConfigurationProperties(prefix = "spring.ai")
public class LlmProviderProperties {

    private Openai openai = new Openai();
    private Ollama ollama = new Ollama();
    private Anthropic anthropic = new Anthropic();

    @Getter
    @Setter
    public static class Openai {
        private String apiKey = "";
        private String baseUrl = "https://api.openai.com";
        private boolean enabled = true;
    }

    @Getter
    @Setter
    public static class Ollama {
        private String baseUrl = "http://localhost:11434";
        private boolean enabled = true;
        private int chatMaxConcurrent = 1;
        private long chatAcquireTimeoutMs = 1000;
        private int chatRetryAttempts = 1;
        private long chatRetryDelayMs = 250;
        private int chatBusyTripThreshold = 2;
        private long chatCircuitOpenMs = 2000;
        private int embeddingMaxConcurrent = 1;
        private long embeddingAcquireTimeoutMs = 1000;
        private int embeddingRetryAttempts = 1;
        private long embeddingRetryDelayMs = 250;
        private int embeddingBusyTripThreshold = 2;
        private long embeddingCircuitOpenMs = 2000;
    }

    @Getter
    @Setter
    public static class Anthropic {
        private String apiKey = "";
        private String baseUrl = "https://api.anthropic.com";
        private boolean enabled = true;
    }
}
