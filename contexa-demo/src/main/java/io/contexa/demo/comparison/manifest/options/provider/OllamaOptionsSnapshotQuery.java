package io.contexa.demo.comparison.manifest.options.provider;

import io.contexa.demo.comparison.manifest.options.support.AbstractChatOptionsSnapshotQuery;
import io.contexa.demo.shared.document.DocumentCodec;
import org.springframework.ai.chat.prompt.ChatOptions;
import org.springframework.ai.ollama.api.OllamaChatOptions;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

@Component
@Profile("contexa")
public class OllamaOptionsSnapshotQuery extends AbstractChatOptionsSnapshotQuery {

    public OllamaOptionsSnapshotQuery(DocumentCodec documents) {
        super(documents);
    }

    @Override
    public boolean supports(ChatOptions options) {
        return options.getClass() == OllamaChatOptions.class;
    }

    @Override
    protected Map<String, Object> scalarValues(ChatOptions source) {
        OllamaChatOptions options = (OllamaChatOptions) source;
        Map<String, Object> values = commonValues(options);
        values.put("keepAlive", options.getKeepAlive());
        values.put("useNUMA", options.getUseNUMA());
        values.put("numCtx", options.getNumCtx());
        values.put("numBatch", options.getNumBatch());
        values.put("numGPU", options.getNumGPU());
        values.put("mainGPU", options.getMainGPU());
        values.put("lowVRAM", options.getLowVRAM());
        values.put("f16KV", options.getF16KV());
        values.put("logitsAll", options.getLogitsAll());
        values.put("vocabOnly", options.getVocabOnly());
        values.put("useMMap", options.getUseMMap());
        values.put("useMLock", options.getUseMLock());
        values.put("numThread", options.getNumThread());
        values.put("numKeep", options.getNumKeep());
        values.put("seed", options.getSeed());
        values.put("numPredict", options.getNumPredict());
        values.put("minP", options.getMinP());
        values.put("tfsZ", options.getTfsZ());
        values.put("typicalP", options.getTypicalP());
        values.put("repeatLastN", options.getRepeatLastN());
        values.put("repeatPenalty", options.getRepeatPenalty());
        values.put("mirostat", options.getMirostat());
        values.put("mirostatTau", options.getMirostatTau());
        values.put("mirostatEta", options.getMirostatEta());
        values.put("penalizeNewline", options.getPenalizeNewline());
        values.put("truncate", options.getTruncate());
        values.put("internalToolExecutionEnabled", options.getInternalToolExecutionEnabled());
        return values;
    }

    @Override
    protected Map<String, Object> fingerprintValues(ChatOptions source) {
        OllamaChatOptions options = (OllamaChatOptions) source;
        Map<String, Object> values = new TreeMap<>();
        values.put("format", options.getFormat());
        values.put("thinkOption", options.getThinkOption());
        values.put("stopSequences", options.getStopSequences());
        values.put("toolNames", options.getToolNames() == null ? null : options.getToolNames().stream().sorted().toList());
        return values;
    }

    @Override
    protected Map<String, Object> unsupportedValues(ChatOptions source) {
        OllamaChatOptions options = (OllamaChatOptions) source;
        Map<String, Object> values = new TreeMap<>();
        values.put("toolContext", options.getToolContext());
        values.put("toolCallbacks", options.getToolCallbacks());
        return values;
    }

    @Override
    protected Set<String> excludedGetters() {
        return Set.of();
    }
}
