package io.contexa.sandbox.fullstack.prompt;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.std.llm.config.LLMClient;
import org.springframework.ai.ollama.api.OllamaApi;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.web.client.RestClient;

@TestConfiguration(proxyBeanMethods = false)
public class SandboxDecisionRealLlmTestConfiguration {

    @Bean
    public SandboxRealLlmExecutionAspect sandboxRealLlmExecutionAspect() {
        return new SandboxRealLlmExecutionAspect();
    }

    @Bean
    public SandboxPromptHarvestBoundaryAspect sandboxPromptHarvestBoundaryAspect(ObjectMapper objectMapper) {
        return new SandboxPromptHarvestBoundaryAspect(objectMapper);
    }

    @Bean
    public SandboxPromptHarvestLayer2ShortCircuitAspect sandboxPromptHarvestLayer2ShortCircuitAspect() {
        return new SandboxPromptHarvestLayer2ShortCircuitAspect();
    }

    @Bean
    public SandboxPromptTruthRealLlmDecisionReplayExecutor sandboxPromptTruthRealLlmDecisionReplayExecutor(
            LLMClient llmClient,
            ObjectMapper objectMapper) {
        return new SandboxPromptTruthRealLlmDecisionReplayExecutor(llmClient, objectMapper);
    }

    @Bean
    @Primary
    public OllamaApi sandboxTimedOllamaApi(
            @Value("${spring.ai.ollama.base-url:http://localhost:11434}") String baseUrl) {
        SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
        requestFactory.setConnectTimeout(10_000);
        requestFactory.setReadTimeout(SandboxDecisionBenchmarkSettings.llmTimeoutSeconds() * 1000);
        RestClient.Builder restClientBuilder = RestClient.builder().requestFactory(requestFactory);
        return OllamaApi.builder()
                .baseUrl(baseUrl)
                .restClientBuilder(restClientBuilder)
                .build();
    }
}
