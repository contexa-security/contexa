package io.contexa.demo.comparison.manifest.options.support;

import io.contexa.demo.comparison.manifest.options.dto.ChatOptionsSnapshot;
import io.contexa.demo.comparison.manifest.options.source.ChatOptionsSnapshotQuery;
import io.contexa.demo.shared.document.DocumentCodec;
import org.springframework.ai.chat.prompt.ChatOptions;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

public abstract class AbstractChatOptionsSnapshotQuery implements ChatOptionsSnapshotQuery {

    private final DocumentCodec documents;

    protected AbstractChatOptionsSnapshotQuery(DocumentCodec documents) {
        this.documents = documents;
    }

    protected abstract Map<String, Object> scalarValues(ChatOptions options);

    protected abstract Map<String, Object> fingerprintValues(ChatOptions options);

    protected abstract Map<String, Object> unsupportedValues(ChatOptions options);

    protected abstract Set<String> excludedGetters();

    @Override
    public ChatOptionsSnapshot capture(ChatOptions options) {
        Map<String, Object> scalars = scalarValues(options);
        Map<String, Object> bodies = fingerprintValues(options);
        Map<String, Object> unsupported = unsupportedValues(options);
        Map<String, Object> values = new TreeMap<>();
        Map<String, String> fingerprints = new TreeMap<>();
        List<String> unset = new ArrayList<>();
        List<String> incomplete = new ArrayList<>();
        scalars.forEach((name, value) -> {
            if (value == null) {
                unset.add(name);
            } else {
                values.put(name, value);
            }
        });
        bodies.forEach((name, value) -> {
            if (value == null) {
                unset.add(name);
            } else {
                fingerprints.put(name, documents.hash(documents.write(value)));
            }
        });
        unsupported.forEach((name, value) -> {
            if (isEmpty(value)) {
                unset.add(name);
            } else {
                incomplete.add(name);
            }
        });
        Set<String> reviewed = new HashSet<>(excludedGetters());
        reviewed.add("getClass");
        reviewed.add("getStop");
        for (Map<String, Object> group : List.of(scalars, bodies, unsupported)) {
            group.keySet().forEach(name -> reviewed.add("get" + Character.toUpperCase(name.charAt(0)) + name.substring(1)));
        }
        Arrays.stream(options.getClass().getMethods())
                .filter(method -> method.getParameterCount() == 0 && method.getName().startsWith("get"))
                .map(Method::getName).filter(name -> !reviewed.contains(name))
                .distinct().sorted().forEach(incomplete::add);
        return new ChatOptionsSnapshot(incomplete.isEmpty() ? "CAPTURED" : "INCOMPLETE",
                options.getClass().getName(), Map.copyOf(values), Map.copyOf(fingerprints),
                unset.stream().sorted().toList(), incomplete.stream().sorted().toList(),
                excludedGetters().stream().sorted().toList());
    }

    protected Map<String, Object> commonValues(ChatOptions options) {
        Map<String, Object> values = new TreeMap<>();
        values.put("model", options.getModel());
        values.put("temperature", options.getTemperature());
        values.put("topP", options.getTopP());
        values.put("topK", options.getTopK());
        values.put("maxTokens", options.getMaxTokens());
        values.put("frequencyPenalty", options.getFrequencyPenalty());
        values.put("presencePenalty", options.getPresencePenalty());
        return values;
    }

    private boolean isEmpty(Object value) {
        return value == null || value instanceof Collection<?> collection && collection.isEmpty()
                || value instanceof Map<?, ?> map && map.isEmpty();
    }
}
