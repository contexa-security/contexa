package io.contexa.contexaiam.aiam.labs.data;

import io.contexa.contexaiam.aiam.labs.studio.domain.DataCollectionPlan;
import io.contexa.contexaiam.aiam.labs.studio.domain.IAMDataSet;
import io.contexa.contexaiam.aiam.protocol.request.PolicyGenerationItem;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@RequiredArgsConstructor
public class IAMDataCollectionService {

    private final StudioQueryCollectionService studioQueryCollectionService;
    private final PolicyGenerationCollectionService policyGenerationCollectionService;

    
    @Transactional(readOnly = true)
    public IAMDataSet studioCollectData(DataCollectionPlan plan) {
        return studioQueryCollectionService.collectData(plan);
    }

    @Transactional(readOnly = true)
    public PolicyGenerationItem.AvailableItems policyCollectData() {
        return policyGenerationCollectionService.collectData();
    }
}