package io.contexa.contexaiam.aiam.web;

import io.contexa.contexacore.std.operations.AINativeProcessor;
import io.contexa.contexacore.domain.SoarContext;
import io.contexa.contexacore.domain.entity.SoarIncident;
import io.contexa.contexacore.domain.SoarRequest;
import io.contexa.contexacore.domain.SoarResponse;
import io.contexa.contexaiam.aiam.service.SoarIncidentService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/soar/incidents")
//@PreAuthorize("hasRole('ROLE_SOAR_ADMIN')")
public class SoarIncidentController {

    private final SoarIncidentService incidentService;
    private final AINativeProcessor aiNativeProcessor; // AINativeProcessor 주입

    public SoarIncidentController(SoarIncidentService incidentService, AINativeProcessor aiNativeProcessor) {
        this.incidentService = incidentService;
        this.aiNativeProcessor = aiNativeProcessor;
    }

    @PostMapping("/create")
    public ResponseEntity<SoarIncident> createIncident(@RequestBody CreateIncidentRequest request) {
        SoarIncident incident = incidentService.createIncident(request.title(), request.playbookId(), request.eventData());
        return ResponseEntity.ok(incident);
    }

    @GetMapping
    public ResponseEntity<List<SoarIncident>> getActiveIncidents() {
        return ResponseEntity.ok(incidentService.getActiveIncidents());
    }

    @GetMapping("/{incidentId}")
    public ResponseEntity<SoarIncident> getIncidentDetails(@PathVariable UUID incidentId) {
        return ResponseEntity.ok(incidentService.getIncident(incidentId));
    }

    // 새로운 SOAR 프로세스 시작 엔드포인트
    @PostMapping("/start")
    public ResponseEntity<SoarResponse> startSoarProcess(@RequestBody StartSoarProcessRequest request) {
        // SoarContext 생성 (초기 데이터 포함)
        SoarContext soarContext = new SoarContext(
                UUID.randomUUID().toString(), // incidentId
                request.threatType(),
                request.description(),
                request.affectedAssets(),
                "INITIAL", // currentStatus
                request.detectedSource(),
                request.severity(),
                request.recommendedActions(),
                request.organizationId()
        );

        // SoarRequest 생성
        SoarRequest soarRequest = new SoarRequest(soarContext, "startSoar", request.initialQuery());
        soarRequest.setMetadata(request.metadata());

        // AINativeProcessor를 통해 SOAR 프로세스 시작
        SoarResponse response = (SoarResponse) aiNativeProcessor.process(soarRequest, SoarResponse.class).block();
        return ResponseEntity.ok(response);
    }

    public record CreateIncidentRequest(String title, String playbookId, Map<String, Object> eventData) {}

    // SOAR 프로세스 시작 요청을 위한 DTO
    public record StartSoarProcessRequest(
            String initialQuery,
            String threatType,
            String description,
            List<String> affectedAssets,
            String detectedSource,
            String severity,
            String recommendedActions,
            String organizationId,
            Map<String, Object> metadata
    ) {}
}
