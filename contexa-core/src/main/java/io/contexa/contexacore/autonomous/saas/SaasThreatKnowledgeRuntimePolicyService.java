package io.contexa.contexacore.autonomous.saas;

import io.contexa.contexacore.autonomous.saas.client.SaasThreatKnowledgeRuntimePolicyHttpClient;
import io.contexa.contexacore.autonomous.saas.dto.ThreatKnowledgeRuntimePolicySnapshot;
import io.contexa.contexacore.properties.SaasForwardingProperties;
import lombok.extern.slf4j.Slf4j;

import java.time.LocalDateTime;
import java.util.LinkedHashSet;
import java.util.Set;

@Slf4j
public class SaasThreatKnowledgeRuntimePolicyService {

    private final SaasForwardingProperties properties;
    private final SaasThreatKnowledgeRuntimePolicyHttpClient httpClient;

    private volatile CachedThreatKnowledgeRuntimePolicy cachedPolicy =
            new CachedThreatKnowledgeRuntimePolicy(ThreatKnowledgeRuntimePolicySnapshot.empty(), null);

    public SaasThreatKnowledgeRuntimePolicyService(
            SaasForwardingProperties properties,
            SaasThreatKnowledgeRuntimePolicyHttpClient httpClient) {
        this.properties = properties;
        this.httpClient = httpClient;
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
            ThreatKnowledgeRuntimePolicySnapshot snapshot =
                    httpClient.fetchRuntimePolicy(properties.getThreatKnowledge().getCaseLimit());
            cachedPolicy = new CachedThreatKnowledgeRuntimePolicy(snapshot, LocalDateTime.now());
        }
        catch (Exception ex) {
            log.error("Failed to refresh SaaS threat knowledge runtime policy", ex);
        }
    }

    public ThreatKnowledgeRuntimePolicySnapshot currentSnapshot() {
        return cachedPolicy.snapshot();
    }

    public boolean isRuntimeAllowed() {
        if (!isEnabled()) {
            return false;
        }
        CachedThreatKnowledgeRuntimePolicy snapshot = cachedPolicy;
        if (!snapshot.isUsable(properties.getThreatKnowledge().getCacheTtlMinutes())) {
            return false;
        }
        ThreatKnowledgeRuntimePolicySnapshot policy = snapshot.snapshot();
        return policy != null
                && policy.featureEnabled()
                && policy.sharingEnabled()
                && policy.runtimeAllowed()
                && !policy.killSwitchActive();
    }

    public Set<String> approvedSignalKeys() {
        return collectSignalKeys("ALLOW_RUNTIME");
    }

    public Set<String> withdrawnSignalKeys() {
        return collectSignalKeys("WITHDRAW");
    }

    private Set<String> collectSignalKeys(String deploymentAction) {
        Set<String> signalKeys = new LinkedHashSet<>();
        if (!isRuntimeAllowed()) {
            return signalKeys;
        }
        for (ThreatKnowledgeRuntimePolicySnapshot.ArtifactPolicyItem artifact : currentSnapshot().artifacts()) {
            if (deploymentAction.equals(artifact.deploymentAction()) && artifact.signalKey() != null && !artifact.signalKey().isBlank()) {
                signalKeys.add(artifact.signalKey());
            }
        }
        return signalKeys;
    }

    private record CachedThreatKnowledgeRuntimePolicy(
            ThreatKnowledgeRuntimePolicySnapshot snapshot,
            LocalDateTime fetchedAt) {

        private boolean isUsable(int cacheTtlMinutes) {
            if (snapshot == null || fetchedAt == null) {
                return false;
            }
            return !fetchedAt.isBefore(LocalDateTime.now().minusMinutes(cacheTtlMinutes));
        }
    }
}
