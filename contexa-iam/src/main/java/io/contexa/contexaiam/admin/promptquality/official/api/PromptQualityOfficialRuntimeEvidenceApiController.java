package io.contexa.contexaiam.admin.promptquality.official.api;

import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexaiam.admin.promptquality.official.application.PromptQualityRuntimeEvidenceService;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidencePackageSummary;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceSearchCriteria;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/contexa/admin/api/prompt-quality/runtime-evidence")
public class PromptQualityOfficialRuntimeEvidenceApiController {

    private final PromptQualityRuntimeEvidenceService runtimeEvidenceService;
    private final PromptQualityOfficialConsoleViewAssembler views;

    public PromptQualityOfficialRuntimeEvidenceApiController(
            PromptQualityRuntimeEvidenceService runtimeEvidenceService,
            PromptQualityOfficialConsoleViewAssembler views) {
        this.runtimeEvidenceService = runtimeEvidenceService;
        this.views = views;
    }

    @GetMapping("/search")
    public List<RuntimeEvidencePackageSummary> searchRuntimeEvidence(
            @RequestParam(required = false) String packageId,
            @RequestParam(required = false) String tenantId,
            @RequestParam(required = false) String userId,
            @RequestParam(required = false) String resourceUrl,
            @RequestParam(required = false) String resourceId,
            @RequestParam(required = false) String httpMethod,
            @RequestParam(required = false) String from,
            @RequestParam(required = false) String to,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        return runtimeEvidenceService.search(new RuntimeEvidenceSearchCriteria(
                packageId,
                tenantId,
                userId,
                resourceUrl,
                resourceId,
                httpMethod,
                views.parseInstant(from, null),
                views.parseInstant(to, null),
                page,
                size));
    }

    @GetMapping("/{packageId}")
    public Map<String, Object> runtimeEvidenceDetail(@PathVariable String packageId) {
        SealedEvidencePackage evidencePackage = views.findPackage(packageId);
        Map<String, Object> detail = new LinkedHashMap<>();
        detail.put("summary", views.evidenceSummary(evidencePackage));
        detail.put("qualityWarnings", List.of());
        detail.put("rawSystemPromptCaptured", StringUtils.hasText(evidencePackage.getRawSystemPrompt()));
        detail.put("rawUserPromptCaptured", StringUtils.hasText(evidencePackage.getRawUserPrompt()));
        detail.put("llmSystemPromptCaptured", StringUtils.hasText(evidencePackage.getSystemPromptText()));
        detail.put("llmUserPromptCaptured", StringUtils.hasText(evidencePackage.getUserPromptText()));
        detail.put("systemPromptPreview", views.preview(evidencePackage.getSystemPromptText()));
        detail.put("userPromptPreview", views.preview(evidencePackage.getUserPromptText()));
        detail.put("promptConsistency", views.promptConsistency(evidencePackage));
        detail.put("sealedEvidence", views.sealedEvidenceMap(evidencePackage));
        return detail;
    }
}