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
        log.info("IAM Command Center: Starting resource synchronization on application startup...");
        try {
            

            log.info("IAM Command Center: Resource synchronization started (async).");

            
            List<Policy> policiesToUpdate = policyRepository.findByFriendlyDescriptionIsNull();

            if (policiesToUpdate.isEmpty()) {
                log.info("All policies have friendly descriptions. No updates needed.");
                return;
            }

            log.info("Found {} policies to enrich. Starting process...", policiesToUpdate.size());
            for (Policy policy : policiesToUpdate) {
                policyEnrichmentService.enrichPolicyWithFriendlyDescription(policy);
                policyRepository.save(policy);
            }
            log.info("Policy enrichment process completed.");
        } catch (Exception e) {
            log.error("IAM Command Center: Failed to initialize resources on startup.", e);
        }
    }
}
