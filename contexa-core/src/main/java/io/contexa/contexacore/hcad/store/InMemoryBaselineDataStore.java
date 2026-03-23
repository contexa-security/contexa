package io.contexa.contexacore.hcad.store;

import io.contexa.contexacommon.hcad.domain.BaselineVector;

import java.util.concurrent.ConcurrentHashMap;

public class InMemoryBaselineDataStore implements BaselineDataStore {

    private final ConcurrentHashMap<String, BaselineVector> userBaselines = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, BaselineVector> orgBaselines = new ConcurrentHashMap<>();

    @Override
    public BaselineVector getUserBaseline(String userId) {
        return userBaselines.get(userId);
    }

    @Override
    public void saveUserBaseline(String userId, BaselineVector baseline) {
        userBaselines.put(userId, baseline);
    }

    @Override
    public BaselineVector getOrganizationBaseline(String organizationId) {
        return orgBaselines.get(organizationId);
    }

    @Override
    public void saveOrganizationBaseline(String organizationId, BaselineVector baseline) {
        orgBaselines.put(organizationId, baseline);
    }

    @Override
    public Iterable<BaselineVector> listOrganizationBaselines() {
        return orgBaselines.values();
    }

    @Override
    public long countUserBaselines() {
        return userBaselines.size();
    }
}
