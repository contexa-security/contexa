package io.contexa.demo.comparison.manifest.source.engine;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.autoconfigure.properties.ContexaLlmBindingProperties;
import io.contexa.autoconfigure.properties.ContexaLlmSelectionProperties;
import io.contexa.contexacore.config.TieredLLMProperties;
import io.contexa.contexacore.properties.ContexaRagProperties;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.demo.comparison.manifest.source.PolicyConfigurationQuery;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import java.util.Map;
import java.util.TreeMap;

@Component
@Profile("contexa")
public class NativePolicyConfigurationQuery implements PolicyConfigurationQuery {

    private final TieredStrategyProperties tiered;
    private final SecurityZeroTrustProperties security;
    private final ContexaRagProperties rag;
    private final ObjectMapper mapper;
    private final TieredLLMProperties models;
    private final ContexaLlmSelectionProperties selection;
    private final ContexaLlmBindingProperties bindings;

    public NativePolicyConfigurationQuery(TieredStrategyProperties tiered, SecurityZeroTrustProperties security,
            ContexaRagProperties rag, ObjectMapper mapper, TieredLLMProperties models,
            ContexaLlmSelectionProperties selection, ContexaLlmBindingProperties bindings) {
        this.tiered = tiered;
        this.security = security;
        this.rag = rag;
        this.mapper = mapper;
        this.models = models;
        this.selection = selection;
        this.bindings = bindings;
    }

    @Override
    public Map<String, JsonNode> capture() {
        Map<String, JsonNode> values = new TreeMap<>();
        // Only reviewed policy DTOs: no Environment enumeration, provider credentials or client objects.
        values.put("layer1", mapper.valueToTree(tiered.getLayer1()));
        values.put("layer2", mapper.valueToTree(tiered.getLayer2()));
        values.put("promptRuntime", mapper.valueToTree(tiered.getPromptRuntime()));
        values.put("truncation", mapper.valueToTree(tiered.getTruncation()));
        values.put("vectorCache", mapper.valueToTree(tiered.getVectorCache()));
        values.put("zeroTrust", mapper.valueToTree(security));
        values.put("rag", mapper.valueToTree(rag));
        values.put("tieredModels", mapper.valueToTree(models));
        values.put("modelSelection", mapper.valueToTree(selection));
        values.put("explicitModelBindings", mapper.valueToTree(bindings));
        values.put("tier1ResolvedDefaults", mapper.valueToTree(Map.of(
                "timeoutMs", models.getTimeoutForTier(1), "temperature", models.getTemperatureForTier(1))));
        values.put("tier2ResolvedDefaults", mapper.valueToTree(Map.of(
                "timeoutMs", models.getTimeoutForTier(2), "temperature", models.getTemperatureForTier(2))));
        return Map.copyOf(values);
    }
}
