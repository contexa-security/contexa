package io.contexa.demo.workspace.configuration;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;
import java.util.List;
import java.util.UUID;

@Validated
@ConfigurationProperties("lab.workspace")
public record WorkspaceAccessProperties(
        @DefaultValue("false") boolean enabled,
        @DefaultValue("30m") Duration lifetime,
        @DefaultValue("3") @Min(1) @Max(3) int comparisons,
        @DefaultValue("24") @Min(1) @Max(24) int chatTransmissions,
        @DefaultValue("48") @Min(1) @Max(48) int embeddingTransmissions,
        @DefaultValue("60") @Min(1) @Max(60) int workRequests,
        @DefaultValue("131072") @Min(1024) @Max(1048576) int maxProviderRequestBytes,
        @DefaultValue("") String workerSlotId,
        UUID workerGeneration,
        @Valid List<WorkspaceSlotDefinition> slots
) {

    public WorkspaceAccessProperties {
        if (lifetime == null || lifetime.isNegative() || lifetime.isZero()
                || lifetime.compareTo(Duration.ofMinutes(30)) > 0) {
            throw new IllegalArgumentException("Workspace lifetime must be within 30 minutes");
        }
        slots = slots == null ? List.of() : List.copyOf(slots);
        if (slots.size() > 1) {
            throw new IllegalArgumentException("This installation supports one exclusive worker pair");
        }
        if (slots.stream().map(WorkspaceSlotDefinition::id).distinct().count() != slots.size()
                || slots.stream().map(WorkspaceSlotDefinition::generation).distinct().count() != slots.size()
                || slots.stream().flatMap(slot -> List.of(slot.baseline(), slot.contexa()).stream())
                        .distinct().count() != slots.size() * 2L) {
            throw new IllegalArgumentException("Workspace slots must use distinct worker endpoints");
        }
    }
}
