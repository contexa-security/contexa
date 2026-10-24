package io.contexa.showcase.portal.agent;

import org.springframework.ai.anthropic.AnthropicChatModel;
import org.springframework.ai.anthropic.AnthropicChatOptions;
import org.springframework.ai.anthropic.api.AnthropicApi;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.openai.OpenAiChatModel;
import org.springframework.ai.openai.OpenAiChatOptions;
import org.springframework.ai.openai.api.OpenAiApi;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * docs/agent A7-2b: the chat models business agents work with, one per model name, made on first use. The key is the
 * portal's model key (the same company account control D uses); the portal starts without one and only an agent task
 * needs it. Separate from the engine's decision models: the agent is the company's business agent, not Contexa. The
 * provider is OpenAI, or Anthropic when the OpenAI balance is used up (docs/agent 위임결정기록 DD-4).
 */
public class AgentModels {

    public static final String OPENAI = "openai";
    public static final String ANTHROPIC = "anthropic";

    /** The longest answer an Anthropic model may give in one round (Anthropic requires a limit). */
    static final int ANTHROPIC_MAX_TOKENS = 4096;

    private final String provider;
    private final String apiKey;
    private final String baseUrl;
    private final String defaultModel;
    private final String reasoningEffort;
    private final Map<String, ChatModel> models = new ConcurrentHashMap<>();

    /**
     * @param apiKey          the model key; blank when the portal has none (an agent task then fails with that reason)
     * @param baseUrl         the model API's address; blank for OpenAI's own
     * @param defaultModel    the model of a task that names none
     * @param reasoningEffort the reasoning effort the agent's calls ask for; blank for the model's own. OpenAI's chat
     *                        completions take function tools from a reasoning model such as gpt-6-luna only with
     *                        {@code none} (2026-10-23 real-server answer 400, param reasoning_effort)
     */
    public AgentModels(String apiKey, String baseUrl, String defaultModel, String reasoningEffort) {
        this(OPENAI, apiKey, baseUrl, defaultModel, reasoningEffort);
    }

    /**
     * @param provider {@value #OPENAI} or {@value #ANTHROPIC}; the reasoning effort applies to OpenAI only
     */
    public AgentModels(String provider, String apiKey, String baseUrl, String defaultModel, String reasoningEffort) {
        if (!OPENAI.equals(provider) && !ANTHROPIC.equals(provider)) {
            throw new IllegalArgumentException("The business agent's provider is openai or anthropic, not " + provider);
        }
        this.provider = provider;
        this.apiKey = apiKey;
        this.baseUrl = baseUrl;
        this.defaultModel = defaultModel;
        this.reasoningEffort = reasoningEffort;
    }

    public String provider() {
        return provider;
    }

    public String modelOf(String requested) {
        return requested == null || requested.isBlank() ? defaultModel : requested.trim();
    }

    /** The chat model of the name; fails when the portal has no model key. */
    public ChatModel chatModel(String model) {
        if (apiKey == null || apiKey.isBlank()) {
            throw new IllegalStateException("The portal has no model key ("
                    + (ANTHROPIC.equals(provider) ? "ANTHROPIC_API_KEY" : "OPENAI_API_KEY") + "), so no business agent runs");
        }
        if (ANTHROPIC.equals(provider)) {
            return models.computeIfAbsent(model, this::anthropic);
        }
        return models.computeIfAbsent(model, name -> {
            OpenAiApi.Builder api = OpenAiApi.builder().apiKey(apiKey);
            if (baseUrl != null && !baseUrl.isBlank()) {
                api.baseUrl(baseUrl);
            }
            // One tool call at a time, so the work's requests reach the company in the order the agent made them.
            OpenAiChatOptions.Builder options = OpenAiChatOptions.builder().model(name).parallelToolCalls(false);
            if (reasoningEffort != null && !reasoningEffort.isBlank()) {
                options.reasoningEffort(reasoningEffort.trim());
            }
            return OpenAiChatModel.builder().openAiApi(api.build()).defaultOptions(options.build()).build();
        });
    }

    /** One tool at a time, so the work's requests reach the company in the order the agent made them. */
    private ChatModel anthropic(String name) {
        AnthropicApi.Builder api = AnthropicApi.builder().apiKey(apiKey);
        if (baseUrl != null && !baseUrl.isBlank()) {
            api.baseUrl(baseUrl);
        }
        return AnthropicChatModel.builder().anthropicApi(api.build())
                .defaultOptions(AnthropicChatOptions.builder().model(name).maxTokens(ANTHROPIC_MAX_TOKENS)
                        .toolChoice(new AnthropicApi.ToolChoiceAuto(true)).build())
                .build();
    }
}
