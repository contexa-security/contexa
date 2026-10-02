package io.contexa.demo.comparison.manifest.source.engine;

import io.contexa.demo.comparison.manifest.dto.NativeConfigurationSnapshot;
import io.contexa.demo.comparison.manifest.source.NativeConfigurationQuery;
import io.contexa.demo.comparison.manifest.source.ModelConfigurationQuery;
import io.contexa.demo.comparison.manifest.source.PolicyConfigurationQuery;
import io.contexa.demo.shared.document.DocumentCodec;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import java.util.List;
import java.util.Map;

@Component
@Profile("contexa")
public class NativeEngineConfigurationQuery implements NativeConfigurationQuery {

    private final ModelConfigurationQuery models;
    private final PolicyConfigurationQuery policies;
    private final DocumentCodec documents;

    public NativeEngineConfigurationQuery(ModelConfigurationQuery models, PolicyConfigurationQuery policies,
            DocumentCodec documents) {
        this.models = models;
        this.policies = policies;
        this.documents = documents;
    }

    @Override
    public NativeConfigurationSnapshot capture() {
        var modelSnapshot = models.capture();
        var policySnapshot = policies.capture();
        boolean available = modelSnapshot.stream().anyMatch(value -> "CHAT".equals(value.type()))
                && modelSnapshot.stream().filter(value -> "CHAT".equals(value.type()))
                        .allMatch(value -> "CAPTURED".equals(value.state()));
        String hash = documents.hash(documents.write(Map.of("models", modelSnapshot, "policies", policySnapshot)));
        return new NativeConfigurationSnapshot(available ? "CAPTURED" : "INCOMPLETE",
                "LLM_RUNTIME_CATALOG_AND_BOUND_POLICY_BEANS", modelSnapshot, policySnapshot, hash,
                List.of("REVIEWED_DEFAULT_OPTIONS_TRANSPORT_SECRETS_EXCLUDED", "PER_REQUEST_OVERRIDES_CAPTURED_IN_NATIVE_PIPELINE",
                        "PROVIDER_DEFAULTS_FOR_UNSET_OPTIONS_NOT_ASSUMED"));
    }
}
