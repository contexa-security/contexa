package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexaiam.admin.promptquality.official.model.OfficialInspectionRunResponse;

public interface OfficialPromptQualityInspectionService {

    OfficialInspectionRunResponse execute(String packageId, String operatorId);

    OfficialInspectionRunResponse findLatest(String packageId);
}
