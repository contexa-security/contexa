package io.contexa.contexacore.autonomous.saas;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.saas.client.SaasThreatIntelligenceHttpClient;
import io.contexa.contexacore.autonomous.saas.dto.ThreatIntelligenceMatchContext;
import io.contexa.contexacore.autonomous.saas.dto.ThreatIntelligenceSnapshot;
import io.contexa.contexacore.autonomous.saas.threat.ThreatSignalMatcherService;
import io.contexa.contexacore.autonomous.tiered.template.SecurityPromptTemplate;
import io.contexa.contexacore.properties.SaasForwardingProperties;
import lombok.extern.slf4j.Slf4j;

import java.time.LocalDateTime;
import java.util.Comparator;
import java.util.List;

@Slf4j
public class SaasThreatIntelligenceService {

    private final SaasForwardingProperties properties;
    private final SaasThreatIntelligenceHttpClient httpClient;
    private final ThreatSignalMatcherService threatSignalMatcherService;

    private volatile CachedThreatIntelligenceSnapshot cachedSnapshot =
            new CachedThreatIntelligenceSnapshot(ThreatIntelligenceSnapshot.empty(), null);

    public SaasThreatIntelligenceService(
            SaasForwardingProperties properties,
            SaasThreatIntelligenceHttpClient httpClient) {
        this(properties, httpClient, new ThreatSignalMatcherService());
    }

    public SaasThreatIntelligenceService(
            SaasForwardingProperties properties,
            SaasThreatIntelligenceHttpClient httpClient,
            ThreatSignalMatcherService threatSignalMatcherService) {
        this.properties = properties;
        this.httpClient = httpClient;
        this.threatSignalMatcherService = threatSignalMatcherService;
    }

    public boolean isEnabled() {
        return properties.isEnabled()
                && properties.getThreatIntelligence() != null
                && properties.getThreatIntelligence().isEnabled();
    }

    public void refresh() {
        if (!isEnabled()) {
            return;
        }
        try {
            ThreatIntelligenceSnapshot snapshot = httpClient.fetchSignals(properties.getThreatIntelligence().getSignalLimit());
            cachedSnapshot = new CachedThreatIntelligenceSnapshot(snapshot, LocalDateTime.now());
        }
        catch (Exception ex) {
            log.error("Failed to refresh SaaS threat intelligence snapshot", ex);
        }
    }

    public List<ThreatIntelligenceSnapshot.ThreatSignalItem> getPromptSignals() {
        return getUsableSignals().stream()
                .sorted(Comparator
                        .comparing(ThreatIntelligenceSnapshot.ThreatSignalItem::affectedTenantCount, Comparator.reverseOrder())
                        .thenComparing(ThreatIntelligenceSnapshot.ThreatSignalItem::observationCount, Comparator.reverseOrder())
                        .thenComparing(ThreatIntelligenceSnapshot.ThreatSignalItem::lastObservedAt, Comparator.nullsLast(Comparator.reverseOrder())))
                .limit(properties.getThreatIntelligence().getPromptLimit())
                .toList();
    }

    public ThreatIntelligenceMatchContext buildThreatContext(
            SecurityEvent event,
            SecurityPromptTemplate.BehaviorAnalysis behaviorAnalysis) {
        if (!isEnabled() || event == null) {
            return ThreatIntelligenceMatchContext.empty();
        }
        return threatSignalMatcherService.buildContext(
                event,
                behaviorAnalysis,
                getUsableSignals(),
                properties.getThreatIntelligence().getPromptLimit());
    }

    ThreatIntelligenceSnapshot currentSnapshot() {
        return cachedSnapshot.snapshot();
    }

    private List<ThreatIntelligenceSnapshot.ThreatSignalItem> getUsableSignals() {
        if (!isEnabled()) {
            return List.of();
        }
        CachedThreatIntelligenceSnapshot snapshot = cachedSnapshot;
        if (!snapshot.isUsable(properties.getThreatIntelligence().getCacheTtlMinutes())) {
            return List.of();
        }
        ThreatIntelligenceSnapshot data = snapshot.snapshot();
        if (data == null || !data.featureEnabled() || !data.sharingEnabled()) {
            return List.of();
        }
        return data.signals();
    }

    private record CachedThreatIntelligenceSnapshot(
            ThreatIntelligenceSnapshot snapshot,
            LocalDateTime fetchedAt) {

        private boolean isUsable(int cacheTtlMinutes) {
            if (snapshot == null || fetchedAt == null) {
                return false;
            }
            return !fetchedAt.isBefore(LocalDateTime.now().minusMinutes(cacheTtlMinutes));
        }
    }
}
