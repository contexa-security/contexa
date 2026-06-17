package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidencePackageDetail;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidencePackageSummary;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceSearchCriteria;

import java.util.List;

public interface PromptQualityRuntimeEvidenceService {

    List<RuntimeEvidencePackageSummary> search(RuntimeEvidenceSearchCriteria criteria);

    RuntimeEvidencePackageDetail findDetail(String packageId);
}
