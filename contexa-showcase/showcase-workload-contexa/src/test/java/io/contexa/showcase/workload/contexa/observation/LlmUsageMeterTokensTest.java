package io.contexa.showcase.workload.contexa.observation;

import org.junit.jupiter.api.Test;
import org.springframework.ai.anthropic.api.AnthropicApi;
import org.springframework.ai.chat.metadata.DefaultUsage;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Model comparison: the cost ledger counts the prompt tokens of every call as OpenAI counts them. Anthropic reports its
 * prompt cache reads and writes apart from its input tokens, and Spring AI's prompt tokens are the input tokens alone.
 */
class LlmUsageMeterTokensTest {

    @Test
    void anAnthropicCallCountsItsCacheReadsAndWritesAsPromptTokens() {
        DefaultUsage usage = new DefaultUsage(3329, 838, 4167, new AnthropicApi.Usage(3329, 838, 12, 4372));

        assertThat(LlmUsageMeter.promptTokens(usage)).isEqualTo(7713L);
    }

    @Test
    void anOpenAiCallKeepsItsPromptTokens() {
        assertThat(LlmUsageMeter.promptTokens(new DefaultUsage(4337, 212))).isEqualTo(4337L);
    }
}
