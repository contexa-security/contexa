package io.contexa.contexaiam.admin.promptquality.official.common;

import org.springframework.beans.factory.InitializingBean;

public class OfficialMetricPurposeContractCatalogBootstrap implements InitializingBean {

    private final OfficialMetricPurposeContractCatalogWriter writer;

    public OfficialMetricPurposeContractCatalogBootstrap(OfficialMetricPurposeContractCatalogWriter writer) {
        this.writer = writer;
    }

    @Override
    public void afterPropertiesSet() {
        writer.upsertFullMetricContractCatalog();
        writer.assertFullMetricContractCatalogPersisted();
    }
}
