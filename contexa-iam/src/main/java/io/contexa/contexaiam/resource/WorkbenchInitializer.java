package io.contexa.contexaiam.resource;

import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.resource.service.ResourceRegistryService;
import io.contexa.contexaiam.security.xacml.pap.service.PolicyEnrichmentService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;

import java.util.List;

@Slf4j
@RequiredArgsConstructor
public class WorkbenchInitializer implements ApplicationRunner {

    private final ResourceRegistryService resourceRegistryService;
    private final PolicyRepository policyRepository;
    private final PolicyEnrichmentService policyEnrichmentService;

    @Override
    public void run(ApplicationArguments args) throws Exception {
        try {
//            resourceRegistryService.refreshAndSynchronizeResources();
            List<Policy> policiesToUpdate = policyRepository.findByFriendlyDescriptionIsNull();

            if (policiesToUpdate.isEmpty()) return;

            for (Policy policy : policiesToUpdate) {
                policyEnrichmentService.enrichPolicyWithFriendlyDescription(policy);
                policyRepository.save(policy);
            }
        } catch (Exception e) {
            log.error("IAM Command Center: Failed to initialize resources on startup.", e);
        }
    }
}
