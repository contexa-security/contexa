package io.contexa.contexamcp.adapter;

import lombok.extern.slf4j.Slf4j;

import java.util.Collections;

/**
 * Default no-op threat intelligence adapter.
 * Used when no external threat intelligence provider is configured.
 * Returns empty results for all queries.
 */
@Slf4j
public class NoOpThreatIntelligenceAdapter implements ThreatIntelligenceAdapter {

    @Override
    public QueryResult queryIndicator(String indicator, String indicatorType) {
        log.error("No external threat intelligence provider configured. indicator={}, type={}", indicator, indicatorType);
        return new QueryResult(
                false, "unknown", 0.0, null, null,
                Collections.emptyList(), Collections.emptyMap(), "none"
        );
    }

    @Override
    public boolean isAvailable() {
        return false;
    }

    @Override
    public String getProviderName() {
        return "NoOp";
    }
}
