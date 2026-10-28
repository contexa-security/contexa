package io.contexa.showcase.workload.contexa.observation;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.std.llm.observation.LlmObservationContext;
import org.junit.jupiter.api.Test;
import org.springframework.ai.anthropic.api.AnthropicApi;
import org.springframework.ai.chat.client.ChatClientRequest;
import org.springframework.ai.chat.client.ChatClientResponse;
import org.springframework.ai.chat.client.advisor.api.CallAdvisorChain;
import org.springframework.ai.chat.messages.AssistantMessage;
import org.springframework.ai.chat.metadata.ChatResponseMetadata;
import org.springframework.ai.chat.metadata.DefaultUsage;
import org.springframework.ai.chat.metadata.Usage;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.chat.model.Generation;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.ai.openai.api.OpenAiApi;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * docs/agent Agent중심-화면 AC-8: the usage ledger of control D keeps the prompt tokens the provider served from its
 * prompt cache next to the prompt tokens, so the portal's cost ledger can price them by the cached input price. A
 * provider that reports none leaves the count unknown, which is not zero.
 */
class LlmUsageMeterCachedTokensTest {

    private static final String DECISION = "11111111-1111-1111-1111-111111111111";

    private final UsageLedger ledger = new UsageLedger();
    private final LlmUsageMeter meter = new LlmUsageMeter(ledger,
            new ModelExchanges(Clock.fixed(Instant.parse("2026-10-27T00:00:00Z"), ZoneOffset.UTC), new ObjectMapper()),
            Clock.fixed(Instant.parse("2026-10-27T00:00:00Z"), ZoneOffset.UTC));

    private UsageLedger.ModelCall call(Usage usage) {
        ChatClientRequest request = ChatClientRequest.builder().prompt(new Prompt("is this request normal?"))
                .context(Map.of(LlmObservationContext.CONTEXT_KEY, observation())).build();
        ChatResponse chat = ChatResponse.builder().generations(List.of(new Generation(new AssistantMessage("ALLOW"))))
                .metadata(ChatResponseMetadata.builder().model("gpt-6-luna").usage(usage).build()).build();
        CallAdvisorChain chain = mock(CallAdvisorChain.class);
        when(chain.nextCall(any())).thenReturn(ChatClientResponse.builder().chatResponse(chat).build());

        meter.adviseCall(request, chain);

        return ledger.callsOf(DECISION).get(0);
    }

    private static LlmObservationContext observation() {
        return new LlmObservationContext(null, DECISION, null, null);
    }

    @Test
    void anOpenAiCallKeepsTheCachedPromptTokensTheProviderReported() {
        UsageLedger.ModelCall call = call(new DefaultUsage(4337, 212, 4549, new OpenAiApi.Usage(212, 4337, 4549,
                new OpenAiApi.Usage.PromptTokensDetails(null, 3840), null)));

        assertThat(call.promptTokens()).isEqualTo(4337L);
        assertThat(call.cachedPromptTokens()).isEqualTo(3840L);
    }

    @Test
    void anAnthropicCallKeepsItsCacheReadsAsCachedPromptTokens() {
        UsageLedger.ModelCall call = call(new DefaultUsage(3329, 838, 4167,
                new AnthropicApi.Usage(3329, 838, 12, 4372)));

        assertThat(call.promptTokens()).as("input, cache reads and writes").isEqualTo(7713L);
        assertThat(call.cachedPromptTokens()).isEqualTo(4372L);
    }

    @Test
    void aProviderThatReportsNoCachedTokensLeavesThemUnknown() {
        UsageLedger.ModelCall call = call(new DefaultUsage(4337, 212));

        assertThat(call.cachedPromptTokens()).isNull();
    }
}
