package io.contexa.autoconfigure.capability;

import io.contexa.contexacommon.autoconfigure.capability.CapabilityCheckResult;
import io.contexa.contexacommon.autoconfigure.capability.CapabilityMode;
import io.contexa.contexacommon.autoconfigure.capability.CapabilityStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.SmartInitializingSingleton;

import java.util.List;
import java.util.stream.Collectors;

public class ContexaAutoConfigurationIntegrityVerifier implements SmartInitializingSingleton {

    private static final Logger log = LoggerFactory.getLogger(ContexaAutoConfigurationIntegrityVerifier.class);

    private final ContexaCapabilityRegistry registry;
    private final CapabilityRequirementResolver requirementResolver;

    public ContexaAutoConfigurationIntegrityVerifier(
            ContexaCapabilityRegistry registry,
            CapabilityRequirementResolver requirementResolver) {
        this.registry = registry;
        this.requirementResolver = requirementResolver;
    }

    @Override
    public void afterSingletonsInstantiated() {
        CapabilityMode mode = requirementResolver.effectiveMode();
        if (mode == CapabilityMode.OFF) {
            return;
        }

        List<CapabilityCheckResult> results = registry.evaluate();
        List<CapabilityCheckResult> abnormalResults = results.stream()
                .filter(result -> result.status() == CapabilityStatus.DEGRADED
                        || result.status() == CapabilityStatus.INACTIVE_UNEXPECTED
                        || result.status() == CapabilityStatus.FAILED)
                .filter(result -> result.required() || mode == CapabilityMode.STRICT)
                .toList();

        for (CapabilityCheckResult result : abnormalResults) {
            log.warn("[ContexaCapability] {} status={} required={} missing={} reason={} recommendations={}",
                    result.capability().propertyKey(),
                    result.status(),
                    result.required(),
                    result.missingBeans(),
                    result.reason(),
                    result.recommendations());
        }

        List<CapabilityCheckResult> failures = results.stream()
                .filter(result -> result.shouldFail(mode))
                .toList();
        if (!failures.isEmpty()) {
            throw new IllegalStateException("Contexa required capability check failed: "
                    + failures.stream()
                    .map(result -> result.capability().propertyKey() + " missing=" + result.missingBeans())
                    .collect(Collectors.joining("; ")));
        }
    }
}
