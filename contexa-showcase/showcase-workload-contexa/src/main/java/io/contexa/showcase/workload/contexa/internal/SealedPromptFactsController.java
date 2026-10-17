package io.contexa.showcase.workload.contexa.internal;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageRepository;
import io.contexa.contexacore.verification.inspection.PromptInspectionRecord;
import io.contexa.contexacore.verification.inspection.PromptInspectionReinspection;
import io.contexa.contexacore.verification.inspection.PromptInspectionResultStore;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * W6-1 (P6-CHANGE-2): the sealed prompt of a decision for the measurement harness, read through the OSS prompt parser
 * (internal API, guarded like every {@code /internal/**} path). Not found when the decision was not sealed.
 */
@RestController
public class SealedPromptFactsController {

    private final ObjectProvider<SealedEvidencePackageRepository> packages;
    private final ObjectProvider<PromptInspectionResultStore> inspections;
    private final ObjectProvider<PromptInspectionReinspection> reinspection;
    private final ObjectMapper objectMapper;

    public SealedPromptFactsController(ObjectProvider<SealedEvidencePackageRepository> packages,
                                       ObjectProvider<PromptInspectionResultStore> inspections,
                                       ObjectProvider<PromptInspectionReinspection> reinspection,
                                       ObjectMapper objectMapper) {
        this.packages = packages;
        this.inspections = inspections;
        this.reinspection = reinspection;
        this.objectMapper = objectMapper;
    }

    @GetMapping("/internal/decisions/{requestId}/prompt-facts")
    public ResponseEntity<Map<String, Object>> promptFacts(@PathVariable("requestId") String requestId) {
        SealedEvidencePackageRepository repository = packages.getIfAvailable();
        Optional<SealedEvidencePackage> sealed = repository != null ? repository.findByCorrelationId(requestId)
                : Optional.empty();
        if (sealed.isEmpty()) {
            return ResponseEntity.notFound().build();
        }
        PromptInspectionResultStore store = inspections.getIfAvailable();
        List<PromptInspectionRecord> records = store != null ? store.findAll(sealed.get().getPackageId()) : List.of();
        return ResponseEntity.ok(SealedPromptFacts.view(sealed.get(), records, objectMapper));
    }

    /**
     * N-SRC-3: the decision's sealed package inspected at once, while the run's records are still on the host (the
     * portal asks before it cleans the run up). Not found while the package is not stored.
     */
    @PostMapping("/internal/decisions/{requestId}/inspection")
    public ResponseEntity<Map<String, Object>> inspection(@PathVariable("requestId") String requestId) {
        SealedEvidencePackageRepository repository = packages.getIfAvailable();
        PromptInspectionReinspection inspector = reinspection.getIfAvailable();
        Optional<SealedEvidencePackage> sealed = repository != null ? repository.findByCorrelationId(requestId)
                : Optional.empty();
        if (sealed.isEmpty() || inspector == null) {
            return ResponseEntity.notFound().build();
        }
        return inspector.reinspect(sealed.get().getPackageId()).map(result -> {
            Map<String, Object> view = new LinkedHashMap<>();
            view.put("packageId", result.packageId());
            view.put("inspectorVersion", result.inspectorVersion());
            view.put("verdict", result.verdict() != null ? result.verdict().name() : null);
            return ResponseEntity.ok(view);
        }).orElseGet(() -> ResponseEntity.notFound().build());
    }
}
