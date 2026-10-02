package io.contexa.demo.comparison.manifest.source;

import io.contexa.demo.comparison.manifest.dto.RagInventorySnapshot;

public interface RagInventoryQuery {

    RagInventorySnapshot capture();
}
