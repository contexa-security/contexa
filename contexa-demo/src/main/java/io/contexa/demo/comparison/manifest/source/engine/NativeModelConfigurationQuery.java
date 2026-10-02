package io.contexa.demo.comparison.manifest.source.engine;

import io.contexa.contexacore.std.llm.runtime.LlmRuntimeBinding;
import io.contexa.contexacore.std.llm.runtime.LlmRuntimeCatalog;
import io.contexa.demo.comparison.manifest.dto.NativeModelConfiguration;
import io.contexa.demo.comparison.manifest.options.dto.ChatOptionsSnapshot;
import io.contexa.demo.comparison.manifest.options.source.ChatOptionsSnapshotQuery;
import io.contexa.demo.comparison.manifest.source.ModelConfigurationQuery;
import org.springframework.ai.chat.prompt.ChatOptions;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Component
@Profile("contexa")
public class NativeModelConfigurationQuery implements ModelConfigurationQuery {

    private final LlmRuntimeCatalog catalog;
    private final List<ChatOptionsSnapshotQuery> readers;

    public NativeModelConfigurationQuery(LlmRuntimeCatalog catalog, List<ChatOptionsSnapshotQuery> readers) {
        this.catalog = catalog;
        this.readers = List.copyOf(readers);
    }

    @Override
    public List<NativeModelConfiguration> capture() {
        List<NativeModelConfiguration> models = new ArrayList<>();
        catalog.getChatBindings().forEach(binding -> models.add(chat(binding)));
        catalog.getEmbeddingBindings().forEach(binding -> models.add(record(binding, "BINDING_ONLY", null)));
        return List.copyOf(models);
    }

    private NativeModelConfiguration chat(LlmRuntimeBinding binding) {
        try {
            ChatOptions options = catalog.resolveChatModel(binding.getRuntimeId()).getDefaultOptions();
            if (options == null) {
                return record(binding, "OPTIONS_UNAVAILABLE", null);
            }
            List<ChatOptionsSnapshotQuery> supported = readers.stream().filter(reader -> reader.supports(options)).toList();
            if (supported.size() != 1) {
                return record(binding, "UNSUPPORTED_OPTIONS", null);
            }
            ChatOptionsSnapshot snapshot = supported.get(0).capture(options);
            return record(binding, snapshot.state(), snapshot);
        } catch (RuntimeException unavailable) {
            return record(binding, "UNAVAILABLE", null);
        }
    }

    private NativeModelConfiguration record(LlmRuntimeBinding binding, String state, ChatOptionsSnapshot options) {
        return new NativeModelConfiguration(binding.getRuntimeId(), binding.getProvider(), binding.getModelId(),
                binding.getType().name(), binding.isPrimary(), binding.getSource(), state,
                options == null ? Map.of() : options.values(), options);
    }
}
