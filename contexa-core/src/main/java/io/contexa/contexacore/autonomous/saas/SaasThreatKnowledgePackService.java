package io.contexa.contexacore.autonomous.saas;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.saas.client.SaasThreatKnowledgePackHttpClient;
import io.contexa.contexacore.autonomous.saas.dto.ThreatKnowledgePackMatchContext;
import io.contexa.contexacore.autonomous.saas.dto.ThreatKnowledgePackSnapshot;
import io.contexa.contexacore.autonomous.saas.threat.ThreatSignalMatcherService;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate;
import io.contexa.contexacore.properties.SaasForwardingProperties;
import lombok.extern.slf4j.Slf4j;

import java.time.LocalDateTime;
import java.util.List;

@Slf4j
public class SaasThreatKnowledgePackService {

    private final SaasForwardingProperties properties;
    private final SaasThreatKnowledgePackHttpClient httpClient;
    private final ThreatSignalMatcherService threatSignalMatcherService;
    private final SaasThreatKnowledgeRuntimePolicyService runtimePolicyService;

    private volatile CachedThreatKnowledgePack cachedPack =
            new CachedThreatKnowledgePack(ThreatKnowledgePackSnapshot.empty(), null);

    public SaasThreatKnowledgePackService(
            SaasForwardingProperties properties,
            SaasThreatKnowledgePackHttpClient httpClient) {
        this(properties, httpClient, new ThreatSignalMatcherService(), null);
    }

    public SaasThreatKnowledgePackService(
            SaasForwardingProperties properties,
            SaasThreatKnowledgePackHttpClient httpClient,
            ThreatSignalMatcherService threatSignalMatcherService) {
        this(properties, httpClient, threatSignalMatcherService, null);
    }

    public SaasThreatKnowledgePackService(
            SaasForwardingProperties properties,
            SaasThreatKnowledgePackHttpClient httpClient,
            SaasThreatKnowledgeRuntimePolicyService runtimePolicyService) {
        this(properties, httpClient, new ThreatSignalMatcherService(), runtimePolicyService);
    }

    public SaasThreatKnowledgePackService(
            SaasForwardingProperties properties,
            SaasThreatKnowledgePackHttpClient httpClient,
            ThreatSignalMatcherService threatSignalMatcherService,
            SaasThreatKnowledgeRuntimePolicyService runtimePolicyService) {
        this.properties = properties;
        this.httpClient = httpClient;
        this.threatSignalMatcherService = threatSignalMatcherService;
        this.runtimePolicyService = runtimePolicyService;
    }

    public boolean isEnabled() {
        return properties.isEnabled()
                && properties.getThreatKnowledge() != null
                && properties.getThreatKnowledge().isEnabled();
    }

    public void refresh() {
        if (!isEnabled()) {
            return;
        }
        try {
            ThreatKnowledgePackSnapshot snapshot = httpClient.fetchKnowledgePack(properties.getThreatKnowledge().getCaseLimit());
            cachedPack = new CachedThreatKnowledgePack(snapshot, LocalDateTime.now());
        }
        catch (Exception ex) {
            log.error("Failed to refresh SaaS threat knowledge pack", ex);
        }
    }

    public ThreatKnowledgePackSnapshot currentSnapshot() {
        return cachedPack.snapshot();
    }

    public ThreatKnowledgePackMatchContext buildThreatKnowledgeContext(
            SecurityEvent event,
            SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis) {
        if (!isEnabled() || event == null) {
            return ThreatKnowledgePackMatchContext.empty();
        }
        return threatSignalMatcherService.buildKnowledgeContext(
                event,
                behaviorAnalysis,
                getUsableCases(),
                properties.getThreatKnowledge().getPromptLimit());
    }

    private List<ThreatKnowledgePackSnapshot.KnowledgeCaseItem> getUsableCases() {
        if (!isEnabled()) {
            return List.of();
        }
        CachedThreatKnowledgePack snapshot = cachedPack;
        if (!snapshot.isUsable(properties.getThreatKnowledge().getCacheTtlMinutes())) {
            return List.of();
        }
        ThreatKnowledgePackSnapshot data = snapshot.snapshot();
        if (data == null || !data.featureEnabled() || !data.sharingEnabled() || !data.runtimeReady()) {
            return List.of();
        }
        if (runtimePolicyService != null && runtimePolicyService.isEnabled()) {
            if (!runtimePolicyService.isRuntimeAllowed()) {
                return List.of();
            }
            var approvedSignalKeys = runtimePolicyService.approvedSignalKeys();
            var withdrawnSignalKeys = runtimePolicyService.withdrawnSignalKeys();
            List<ThreatKnowledgePackSnapshot.KnowledgeCaseItem> filteredCases = data.cases().stream()
                    .filter(item -> approvedSignalKeys.contains(item.signalKey()))
                    .filter(item -> !withdrawnSignalKeys.contains(item.signalKey()))
                    .toList();
            return filteredCases;
        }
        return data.cases();
    }

    private record CachedThreatKnowledgePack(
            ThreatKnowledgePackSnapshot snapshot,
            LocalDateTime fetchedAt) {

        private boolean isUsable(int cacheTtlMinutes) {
            if (snapshot == null || fetchedAt == null) {
                return false;
            }
            return !fetchedAt.isBefore(LocalDateTime.now().minusMinutes(cacheTtlMinutes));
        }
    }
}
