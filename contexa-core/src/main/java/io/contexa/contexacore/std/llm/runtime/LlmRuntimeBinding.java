package io.contexa.contexacore.std.llm.runtime;

import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;

public final class LlmRuntimeBinding {

    private final String runtimeId;
    private final String beanName;
    private final String provider;
    private final String modelId;
    private final Set<String> aliases;
    private final LlmRuntimeType type;
    private final boolean primary;
    private final String source;

    public LlmRuntimeBinding(
            String runtimeId,
            String beanName,
            String provider,
            String modelId,
            Set<String> aliases,
            LlmRuntimeType type,
            boolean primary,
            String source) {
        this.runtimeId = normalize(runtimeId);
        this.beanName = normalize(beanName);
        this.provider = normalize(provider);
        this.modelId = normalize(modelId);
        this.aliases = aliases == null ? Set.of() : Set.copyOf(new LinkedHashSet<>(aliases.stream()
                .filter(Objects::nonNull)
                .map(String::trim)
                .filter(value -> !value.isEmpty())
                .toList()));
        this.type = type;
        this.primary = primary;
        this.source = normalize(source);
    }

    public String getRuntimeId() {
        return runtimeId;
    }

    public String getBeanName() {
        return beanName;
    }

    public String getProvider() {
        return provider;
    }

    public String getModelId() {
        return modelId;
    }

    public Set<String> getAliases() {
        return aliases;
    }

    public LlmRuntimeType getType() {
        return type;
    }

    public boolean isPrimary() {
        return primary;
    }

    public String getSource() {
        return source;
    }

    public String canonicalId() {
        if (modelId != null) {
            return modelId;
        }
        if (runtimeId != null) {
            return runtimeId;
        }
        return beanName;
    }

    public boolean matches(String selector) {
        String normalized = normalize(selector);
        if (normalized == null) {
            return false;
        }
        return normalized.equals(runtimeId)
                || normalized.equals(beanName)
                || normalized.equals(modelId)
                || aliases.contains(normalized);
    }

    private static String normalize(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }
}