package io.contexa.contexaiam.admin.promptquality.official.common;

import org.springframework.beans.factory.InitializingBean;

public class OfficialMetricPurposeContractCatalogBootstrap implements InitializingBean {

    private final OfficialMetricPurposeContractWriter writer;

    public OfficialMetricPurposeContractCatalogBootstrap(OfficialMetricPurposeContractWriter writer) {
        this.writer = writer;
    }

    @Override
    public void afterPropertiesSet() {
        writer.upsertFullMetricContractCatalog();
        writer.assertFullMetricContractCatalogPersisted();
    }
}
