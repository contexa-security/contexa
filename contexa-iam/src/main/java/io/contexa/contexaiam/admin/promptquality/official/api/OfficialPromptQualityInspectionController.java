package io.contexa.contexaiam.admin.promptquality.official.api;

import io.contexa.contexaiam.admin.promptquality.official.application.OfficialPromptQualityInspectionService;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialInspectionRunRequest;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialInspectionRunResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/contexa/admin/api/prompt-quality/official")
public class OfficialPromptQualityInspectionController {

    private final OfficialPromptQualityInspectionService inspectionService;

    public OfficialPromptQualityInspectionController(OfficialPromptQualityInspectionService inspectionService) {
        this.inspectionService = inspectionService;
    }

    @PostMapping("/runs")
    public OfficialInspectionRunResponse execute(@RequestBody OfficialInspectionRunRequest request) {
        return inspectionService.execute(request.packageId(), request.operatorId());
    }

    @GetMapping("/packages/{packageId}/latest")
    public OfficialInspectionRunResponse latest(@PathVariable String packageId) {
        return inspectionService.findLatest(packageId);
    }
}
