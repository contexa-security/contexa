package io.contexa.contexaiam.admin.promptquality.official.common;

import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceMetricResult;

import java.util.List;

public interface OfficialMetricPurposeContractWriter {

    void upsertFullMetricContractCatalog();

    void upsertRuntimeMetricContractCatalog(List<RuntimeEvidenceMetricResult> metrics);

    void assertFullMetricContractCatalogPersisted();
}