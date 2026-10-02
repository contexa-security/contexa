package io.contexa.demo.comparison.manifest.source.impl;

import io.contexa.demo.comparison.manifest.dto.RagInventorySnapshot;
import io.contexa.demo.comparison.manifest.source.RagInventoryQuery;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import java.time.Instant;

@Component
@Profile("baseline")
public class NoAiRagInventoryQuery implements RagInventoryQuery {

    @Override
    public RagInventorySnapshot capture() {
        return new RagInventorySnapshot("NOT_APPLICABLE", "BASELINE_AI_DISABLED", Instant.now(),
                null, 0, null, "NO_AI_RETRIEVAL");
    }
}
