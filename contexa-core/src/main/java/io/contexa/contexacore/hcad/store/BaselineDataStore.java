package io.contexa.contexacore.hcad.store;

import io.contexa.contexacommon.hcad.domain.BaselineVector;

public interface BaselineDataStore {

    BaselineVector getUserBaseline(String userId);

    void saveUserBaseline(String userId, BaselineVector baseline);

    BaselineVector getOrganizationBaseline(String organizationId);

    void saveOrganizationBaseline(String organizationId, BaselineVector baseline);
}
