package io.contexa.autoconfigure.capability;

import io.contexa.contexacommon.autoconfigure.capability.CapabilityCheckResult;
import io.contexa.contexacommon.autoconfigure.capability.CapabilityContributor;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

public class ContexaCapabilityRegistry {

    private final List<CapabilityContributor> contributors;
    private final AtomicReference<List<CapabilityCheckResult>> lastResults = new AtomicReference<>(List.of());

    public ContexaCapabilityRegistry(List<CapabilityContributor> contributors) {
        this.contributors = contributors == null ? List.of() : List.copyOf(contributors);
    }

    public List<CapabilityCheckResult> evaluate() {
        List<CapabilityCheckResult> results = new ArrayList<>();
        for (CapabilityContributor contributor : contributors) {
            results.addAll(contributor.check());
        }
        results.sort(Comparator.comparing(result -> result.capability().name()));
        List<CapabilityCheckResult> immutableResults = List.copyOf(results);
        lastResults.set(immutableResults);
        return immutableResults;
    }

    public List<CapabilityCheckResult> lastResults() {
        List<CapabilityCheckResult> results = lastResults.get();
        return results.isEmpty() ? evaluate() : results;
    }
}
