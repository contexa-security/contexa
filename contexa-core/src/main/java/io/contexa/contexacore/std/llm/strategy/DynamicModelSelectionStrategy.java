package io.contexa.contexacore.std.llm.strategy;

import io.contexa.contexacore.config.TieredLLMProperties;
import io.contexa.contexacore.std.llm.client.ExecutionContext;
import io.contexa.contexacore.std.llm.exception.ModelSelectionException;
import io.contexa.contexacore.std.llm.model.DynamicModelRegistry;
import io.contexa.contexacore.std.llm.model.ModelDescriptor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.chat.prompt.ChatOptions;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
public class DynamicModelSelectionStrategy implements ModelSelectionStrategy {

    private static final String METADATA_REQUESTED_MODEL_ID = "requestedModelId";
    private static final String METADATA_REQUESTED_MODEL_SOURCE_KEY = "requestedModelSourceKey";
    private static final String METADATA_SELECTED_MODEL_ID = "selectedModelId";
    private static final String METADATA_SELECTED_MODEL_PROVIDER = "selectedModelProvider";
    private static final String METADATA_RUNTIME_MODEL_ID = "runtimeModelId";
    private static final String METADATA_MODEL_SELECTION_SOURCE = "modelSelectionSource";
    private static final String METADATA_MODEL_SELECTION_FALLBACK_USED = "modelSelectionFallbackUsed";
    private static final String METADATA_MODEL_SELECTION_FAILURE = "modelSelectionFailure";
    private static final String METADATA_MODEL_SELECTION_CANDIDATES = "modelSelectionCandidates";

    private final DynamicModelRegistry modelRegistry;
    private final TieredLLMProperties tieredLLMProperties;
    private final ChatModel primaryChatModel;

    public DynamicModelSelectionStrategy(
            DynamicModelRegistry modelRegistry,
            TieredLLMProperties tieredLLMProperties,
            ChatModel primaryChatModel) {
        this.modelRegistry = modelRegistry;
        this.tieredLLMProperties = tieredLLMProperties;
        this.primaryChatModel = primaryChatModel;
    }

    @Override
    public ChatModel selectModel(ExecutionContext context) {
        try {
            Map<String, Object> metadata = ensureMetadata(context);
            clearResolutionMetadata(metadata);
            List<String> candidates = new ArrayList<>();
            boolean fallbackUsed = false;

            ExplicitModelRequest explicitRequest = resolveExplicitModelRequest(context);
            if (explicitRequest != null) {
                metadata.put(METADATA_REQUESTED_MODEL_ID, explicitRequest.modelId());
                metadata.put(METADATA_REQUESTED_MODEL_SOURCE_KEY, explicitRequest.sourceKey());
                ChatModel explicitModel = tryGetModel(explicitRequest.modelId(), candidates);
                if (explicitModel != null) {
                    recordSelection(metadata, explicitRequest.modelId(), resolveProvider(explicitRequest.modelId()), "explicit_model", false, candidates);
                    return explicitModel;
                }
                fallbackUsed = true;
                recordFailure(metadata, candidates, "Requested model not available: " + explicitRequest.modelId());
                log.warn("Requested model {} not available - RequestId: {}", explicitRequest.modelId(), context.getRequestId());
            }

            TierModelCandidate tierCandidate = resolveTierCandidate(context);
            if (tierCandidate != null) {
                ChatModel tierModel = tryGetModel(tierCandidate.primaryModelId(), candidates);
                if (tierModel != null) {
                    recordSelection(metadata, tierCandidate.primaryModelId(), resolveProvider(tierCandidate.primaryModelId()), tierCandidate.source(), fallbackUsed, candidates);
                    return tierModel;
                }
                if (tierCandidate.backupModelId() != null) {
                    ChatModel backupModel = tryGetModel(tierCandidate.backupModelId(), candidates);
                    if (backupModel != null) {
                        recordSelection(metadata, tierCandidate.backupModelId(), resolveProvider(tierCandidate.backupModelId()), tierCandidate.source() + ":backup", true, candidates);
                        return backupModel;
                    }
                    fallbackUsed = true;
                }
            }

            if (primaryChatModel != null) {
                String selectedModelId = inferModelId(primaryChatModel, null);
                recordSelection(metadata, selectedModelId, resolveProvider(selectedModelId), "primary_chat_model", true, candidates);
                return primaryChatModel;
            }

            String failure = "No model available";
            recordFailure(metadata, candidates, failure);
            log.error("{} - RequestId: {}", failure, context.getRequestId());
            return null;

        } catch (Exception e) {
            ensureMetadata(context).put(METADATA_MODEL_SELECTION_FAILURE, e.getMessage());
            log.error("Model selection failed - RequestId: {}", context.getRequestId(), e);
            throw new ModelSelectionException("Error during model selection: " + e.getMessage(), e);
        }
    }

    private ChatModel tryGetModel(String modelId, List<String> candidates) {
        if (!hasText(modelId)) {
            return null;
        }
        String normalizedModelId = modelId.trim();
        candidates.add(normalizedModelId);
        try {
            return modelRegistry.getModel(normalizedModelId);
        } catch (Exception e) {
            log.warn("Model {} unavailable during dynamic selection", normalizedModelId);
            return null;
        }
    }

    private void recordSelection(
            Map<String, Object> metadata,
            String selectedModelId,
            String provider,
            String source,
            boolean fallbackUsed,
            List<String> candidates) {
        metadata.put(METADATA_SELECTED_MODEL_ID, selectedModelId);
        metadata.put(METADATA_RUNTIME_MODEL_ID, selectedModelId);
        metadata.put(METADATA_MODEL_SELECTION_SOURCE, source);
        metadata.put(METADATA_MODEL_SELECTION_FALLBACK_USED, fallbackUsed);
        metadata.put(METADATA_MODEL_SELECTION_CANDIDATES, List.copyOf(candidates));
        if (hasText(provider)) {
            metadata.put(METADATA_SELECTED_MODEL_PROVIDER, provider);
        } else {
            metadata.remove(METADATA_SELECTED_MODEL_PROVIDER);
        }
        if (!fallbackUsed) {
            metadata.remove(METADATA_MODEL_SELECTION_FAILURE);
        }
    }

    private void recordFailure(Map<String, Object> metadata, List<String> candidates, String failure) {
        metadata.put(METADATA_MODEL_SELECTION_CANDIDATES, List.copyOf(candidates));
        metadata.put(METADATA_MODEL_SELECTION_FAILURE, failure);
    }

    private ExplicitModelRequest resolveExplicitModelRequest(ExecutionContext context) {
        if (context == null) {
            return null;
        }
        if (hasText(context.getPreferredModel())) {
            return new ExplicitModelRequest(context.getPreferredModel().trim(), "executionContext.preferredModel");
        }
        Map<String, Object> metadata = ensureMetadata(context);
        for (String key : List.of("requestedModelId", "preferredModel", "runtimeModelId", "modelId")) {
            String value = text(metadata.get(key));
            if (hasText(value)) {
                return new ExplicitModelRequest(value.trim(), "executionContext.metadata." + key);
            }
        }
        return null;
    }

    private TierModelCandidate resolveTierCandidate(ExecutionContext context) {
        if (context == null) {
            return null;
        }

        Integer tier = null;
        String source = null;
        if (context.getAnalysisLevel() != null) {
            tier = context.getAnalysisLevel().getDefaultTier();
            source = "analysis_level:" + context.getAnalysisLevel().name();
        } else if (context.getSecurityTaskType() != null) {
            tier = context.getSecurityTaskType().getDefaultTier();
            source = "security_task_type:" + context.getSecurityTaskType().name();
        } else if (context.getTier() != null) {
            tier = context.getTier();
            source = "tier:" + context.getTier();
        }

        if (tier == null) {
            return null;
        }

        int effectiveTier = normalizeTier(tier);
        String primaryModelId = tieredLLMProperties.getModelNameForTier(effectiveTier);
        if (!hasText(primaryModelId)) {
            return null;
        }
        String backupModelId = tieredLLMProperties.getBackupModelNameForTier(effectiveTier);
        return new TierModelCandidate(primaryModelId.trim(), hasText(backupModelId) ? backupModelId.trim() : null, source);
    }

    private int normalizeTier(int tier) {
        if (tier <= 1) {
            return 1;
        }
        return Math.min(tier, 2);
    }

    private String resolveProvider(String modelId) {
        if (!hasText(modelId)) {
            return null;
        }
        ModelDescriptor descriptor = modelRegistry.getDescriptor(modelId);
        return descriptor != null ? descriptor.getProvider() : null;
    }

    private String inferModelId(ChatModel model, String fallbackModelId) {
        if (model != null) {
            ChatOptions options = model.getDefaultOptions();
            if (options != null && hasText(options.getModel())) {
                return options.getModel().trim();
            }
        }
        return hasText(fallbackModelId) ? fallbackModelId.trim() : (model != null ? model.getClass().getSimpleName() : null);
    }

    private Map<String, Object> ensureMetadata(ExecutionContext context) {
        if (context.getMetadata() == null) {
            context.setMetadata(new HashMap<>());
        }
        return context.getMetadata();
    }

    private void clearResolutionMetadata(Map<String, Object> metadata) {
        metadata.remove(METADATA_SELECTED_MODEL_ID);
        metadata.remove(METADATA_SELECTED_MODEL_PROVIDER);
        metadata.remove(METADATA_RUNTIME_MODEL_ID);
        metadata.remove(METADATA_MODEL_SELECTION_SOURCE);
        metadata.remove(METADATA_MODEL_SELECTION_FALLBACK_USED);
        metadata.remove(METADATA_MODEL_SELECTION_FAILURE);
        metadata.remove(METADATA_MODEL_SELECTION_CANDIDATES);
        metadata.remove(METADATA_REQUESTED_MODEL_SOURCE_KEY);
    }

    private boolean hasText(String value) {
        return value != null && !value.trim().isEmpty();
    }

    private String text(Object value) {
        if (value == null) {
            return null;
        }
        String text = String.valueOf(value);
        return text.isBlank() ? null : text;
    }

    @Override
    public Set<String> getSupportedModels() {
        return modelRegistry.getAllModels().stream()
                .map(ModelDescriptor::getModelId)
                .collect(Collectors.toSet());
    }

    @Override
    public boolean isModelAvailable(String modelName) {
        try {
            return modelRegistry.getModel(modelName) != null;
        } catch (Exception e) {
            return false;
        }
    }

    public Map<String, Object> getModelCapabilities(String modelName) {
        try {
            ModelDescriptor descriptor = modelRegistry.getAllModels().stream()
                    .filter(model -> model.getModelId().equals(modelName))
                    .findFirst()
                    .orElse(null);

            if (descriptor == null) {
                return Map.of();
            }

            Map<String, Object> capabilities = new HashMap<>();
            capabilities.put("modelId", descriptor.getModelId());
            capabilities.put("provider", descriptor.getProvider());
            capabilities.put("capabilities", descriptor.getCapabilities());
            capabilities.put("contextWindow", descriptor.getCapabilities() != null ? descriptor.getCapabilities().getContextWindow() : null);
            capabilities.put("maxTokens", descriptor.getCapabilities() != null ? descriptor.getCapabilities().getMaxTokens() : null);
            capabilities.put("streaming", descriptor.getCapabilities() != null && descriptor.getCapabilities().isStreaming());
            capabilities.put("tier", descriptor.getTier());
            capabilities.put("status", descriptor.getStatus());
            return capabilities;
        } catch (Exception e) {
            log.error("Error getting capabilities for model {}", modelName, e);
            return Map.of();
        }
    }

    private record ExplicitModelRequest(String modelId, String sourceKey) {
    }

    private record TierModelCandidate(String primaryModelId, String backupModelId, String source) {
    }
}
