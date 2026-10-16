package io.contexa.showcase.workload.contexa.internal;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageRepository;
import io.contexa.contexacore.verification.inspection.PromptInspectionRecord;
import io.contexa.contexacore.verification.inspection.PromptInspectionResultStore;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

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
    private final ObjectMapper objectMapper;

    public SealedPromptFactsController(ObjectProvider<SealedEvidencePackageRepository> packages,
                                       ObjectProvider<PromptInspectionResultStore> inspections,
                                       ObjectMapper objectMapper) {
        this.packages = packages;
        this.inspections = inspections;
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
}
