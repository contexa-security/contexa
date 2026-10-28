package io.contexa.showcase.portal.agent;

import org.junit.jupiter.api.Test;
import org.springframework.ai.anthropic.api.AnthropicApi;
import org.springframework.ai.chat.metadata.DefaultUsage;
import org.springframework.ai.openai.api.OpenAiApi;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * docs/agent Agent중심-화면 AC-8: the business agent's tokens are counted the same way for OpenAI and Anthropic, with the
 * prompt cache's share kept apart, as the engine's usage reading does for control D.
 */
class AgentUsageTest {

    @Test
    void anOpenAiUsageKeepsItsPromptTokensAndNamesItsCachedShare() {
        DefaultUsage usage = new DefaultUsage(4337, 212, 4549, new OpenAiApi.Usage(212, 4337, 4549,
                new OpenAiApi.Usage.PromptTokensDetails(null, 3840), null));

        assertThat(AgentUsage.counts(usage)).containsEntry("promptTokens", 4337).containsEntry("completionTokens", 212)
                .containsEntry("totalTokens", 4549).containsEntry("cachedPromptTokens", 3840);
    }

    @Test
    void anAnthropicUsageCountsItsCacheReadsAndWritesAsPromptTokens() {
        DefaultUsage usage = new DefaultUsage(3329, 838, 4167, new AnthropicApi.Usage(3329, 838, 12, 4372));

        assertThat(AgentUsage.counts(usage)).containsEntry("promptTokens", 7713).containsEntry("completionTokens", 838)
                .containsEntry("totalTokens", 8551).containsEntry("cachedPromptTokens", 4372);
    }

    @Test
    void aProviderThatReportsNoCachedTokensLeavesThemOutNotAtZero() {
        assertThat(AgentUsage.counts(new DefaultUsage(100, 10))).containsEntry("promptTokens", 100)
                .doesNotContainKey("cachedPromptTokens");
        assertThat(AgentUsage.counts(new DefaultUsage(4337, 212, 4549,
                new OpenAiApi.Usage(212, 4337, 4549, null, null)))).doesNotContainKey("cachedPromptTokens");
        assertThat(AgentUsage.counts(null)).isEmpty();
    }
}
