package io.contexa.contexaiam.aiam.labs.data;

import io.contexa.contexaiam.aiam.protocol.request.PolicyGenerationItem;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@RequiredArgsConstructor
public class IAMDataCollectionService {

    private final PolicyGenerationCollectionService policyGenerationCollectionService;

    @Transactional(readOnly = true)
    public PolicyGenerationItem.AvailableItems policyCollectData() {
        return policyGenerationCollectionService.collectData();
    }

    @Transactional(readOnly = true)
    public String collectExistingPoliciesSummary() {
        return policyGenerationCollectionService.collectExistingPoliciesSummary();
    }

    public String collectRoleHierarchy() {
        return policyGenerationCollectionService.collectRoleHierarchy();
    }
}
