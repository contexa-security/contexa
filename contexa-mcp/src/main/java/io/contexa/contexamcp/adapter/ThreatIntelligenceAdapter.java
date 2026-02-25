package io.contexa.contexamcp.adapter;

import java.util.List;
import java.util.Map;

/**
 * Adapter interface for external threat intelligence providers.
 * Implementations connect to vendor-specific APIs (VirusTotal, AbuseIPDB, AlienVault OTX, etc.).
 * Default: NoOpThreatIntelligenceAdapter (no external queries).
 */
public interface ThreatIntelligenceAdapter {

    QueryResult queryIndicator(String indicator, String indicatorType);

    boolean isAvailable();

    String getProviderName();

    record QueryResult(
            boolean found,
            String reputation,
            double confidenceScore,
            String malwareFamily,
            String attackCampaign,
            List<String> tags,
            Map<String, Object> context,
            String source
    ) {
    }
}
