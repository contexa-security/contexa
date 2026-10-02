package io.contexa.demo.comparison.manifest.options.provider;

import io.contexa.demo.comparison.manifest.options.support.AbstractChatOptionsSnapshotQuery;
import io.contexa.demo.shared.document.DocumentCodec;
import org.springframework.ai.chat.prompt.ChatOptions;
import org.springframework.ai.openai.OpenAiChatOptions;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

@Component
@Profile("contexa")
public class OpenAiOptionsSnapshotQuery extends AbstractChatOptionsSnapshotQuery {

    public OpenAiOptionsSnapshotQuery(DocumentCodec documents) {
        super(documents);
    }

    @Override
    public boolean supports(ChatOptions options) {
        return options.getClass() == OpenAiChatOptions.class;
    }

    @Override
    protected Map<String, Object> scalarValues(ChatOptions source) {
        OpenAiChatOptions options = (OpenAiChatOptions) source;
        Map<String, Object> values = commonValues(options);
        values.put("maxCompletionTokens", options.getMaxCompletionTokens());
        values.put("reasoningEffort", options.getReasoningEffort());
        values.put("verbosity", options.getVerbosity());
        values.put("seed", options.getSeed());
        values.put("n", options.getN());
        values.put("streamUsage", options.getStreamUsage());
        values.put("logprobs", options.getLogprobs());
        values.put("topLogprobs", options.getTopLogprobs());
        values.put("parallelToolCalls", options.getParallelToolCalls());
        values.put("serviceTier", options.getServiceTier());
        values.put("store", options.getStore());
        values.put("internalToolExecutionEnabled", options.getInternalToolExecutionEnabled());
        return values;
    }

    @Override
    protected Map<String, Object> fingerprintValues(ChatOptions source) {
        OpenAiChatOptions options = (OpenAiChatOptions) source;
        Map<String, Object> values = new TreeMap<>();
        values.put("logitBias", options.getLogitBias());
        values.put("outputModalities", options.getOutputModalities());
        values.put("outputAudio", options.getOutputAudio());
        values.put("responseFormat", options.getResponseFormat());
        values.put("streamOptions", options.getStreamOptions());
        values.put("stopSequences", options.getStopSequences());
        values.put("tools", options.getTools());
        values.put("toolChoice", options.getToolChoice());
        values.put("user", options.getUser());
        values.put("toolNames", options.getToolNames() == null ? null : options.getToolNames().stream().sorted().toList());
        values.put("metadata", options.getMetadata());
        values.put("webSearchOptions", options.getWebSearchOptions());
        values.put("promptCacheKey", options.getPromptCacheKey());
        values.put("safetyIdentifier", options.getSafetyIdentifier());
        values.put("outputSchema", options.getResponseFormat() == null ? null : options.getOutputSchema());
        return values;
    }

    @Override
    protected Map<String, Object> unsupportedValues(ChatOptions source) {
        OpenAiChatOptions options = (OpenAiChatOptions) source;
        Map<String, Object> values = new TreeMap<>();
        values.put("extraBody", options.getExtraBody());
        values.put("toolContext", options.getToolContext());
        values.put("toolCallbacks", options.getToolCallbacks());
        return values;
    }

    @Override
    protected Set<String> excludedGetters() {
        return Set.of("getHttpHeaders");
    }
}
