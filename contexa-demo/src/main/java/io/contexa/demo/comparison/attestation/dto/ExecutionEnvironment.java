package io.contexa.demo.comparison.attestation.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import io.contexa.demo.comparison.manifest.dto.NativeConfigurationSnapshot;
import io.contexa.demo.comparison.manifest.dto.RagInventorySnapshot;
import java.util.Map;
import java.util.UUID;

public record ExecutionEnvironment(
        UUID serverInstanceId,
        String applicationSha256,
        String artifactState,
        Map<String, String> effectiveConfiguration,
        Map<String, String> resourceSha256,
        String migrationSha256,
        @JsonInclude(JsonInclude.Include.NON_NULL) NativeConfigurationSnapshot nativeConfiguration,
        @JsonInclude(JsonInclude.Include.NON_NULL) RagInventorySnapshot ragInventory
) {
}
