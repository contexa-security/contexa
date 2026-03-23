package io.contexa.contexacore.autonomous.saas;

import io.contexa.contexacore.autonomous.saas.client.SaasBaselineSeedHttpClient;
import io.contexa.contexacore.autonomous.saas.dto.BaselineSeedSnapshot;
import io.contexa.contexacore.properties.SaasForwardingProperties;
import lombok.extern.slf4j.Slf4j;

import java.time.LocalDateTime;

@Slf4j
public class SaasBaselineSeedService {

    private final SaasForwardingProperties properties;
    private final SaasBaselineSeedHttpClient httpClient;

    private volatile CachedBaselineSeedSnapshot cachedSnapshot =
            new CachedBaselineSeedSnapshot(BaselineSeedSnapshot.empty(), null);

    public SaasBaselineSeedService(
            SaasForwardingProperties properties,
            SaasBaselineSeedHttpClient httpClient) {
        this.properties = properties;
        this.httpClient = httpClient;
    }

    public boolean isEnabled() {
        return properties.isEnabled()
                && properties.getBaselineSignal() != null
                && properties.getBaselineSignal().isEnabled();
    }

    public void refresh() {
        if (!isEnabled()) {
            return;
        }
        try {
            BaselineSeedSnapshot snapshot = httpClient.fetchSeed();
            cachedSnapshot = new CachedBaselineSeedSnapshot(snapshot, LocalDateTime.now());
        } catch (Exception ex) {
            log.error("Failed to refresh SaaS baseline seed snapshot", ex);
        }
    }

    public BaselineSeedSnapshot getPromptSeed() {
        if (!isEnabled()) {
            return BaselineSeedSnapshot.empty();
        }
        CachedBaselineSeedSnapshot snapshot = cachedSnapshot;
        if (!snapshot.isUsable(properties.getBaselineSignal().getSeedCacheTtlMinutes())) {
            return BaselineSeedSnapshot.empty();
        }
        BaselineSeedSnapshot data = snapshot.snapshot();
        if (data == null || !data.featureEnabled() || !data.seedAvailable()) {
            return BaselineSeedSnapshot.empty();
        }
        return data;
    }

    BaselineSeedSnapshot currentSnapshot() {
        return cachedSnapshot.snapshot();
    }

    private record CachedBaselineSeedSnapshot(
            BaselineSeedSnapshot snapshot,
            LocalDateTime fetchedAt) {

        private boolean isUsable(int cacheTtlMinutes) {
            if (snapshot == null || fetchedAt == null) {
                return false;
            }
            return !fetchedAt.isBefore(LocalDateTime.now().minusMinutes(cacheTtlMinutes));
        }
    }
}
