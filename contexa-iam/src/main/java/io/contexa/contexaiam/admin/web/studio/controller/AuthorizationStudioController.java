package io.contexa.contexaiam.admin.web.studio.controller;

import io.contexa.contexaiam.admin.support.context.dto.GraphDataDto;
import io.contexa.contexaiam.admin.web.studio.dto.ExplorerItemDto;
import io.contexa.contexaiam.admin.web.studio.dto.InitiateGrantRequestDto;
import io.contexa.contexaiam.admin.web.studio.dto.SimulationRequestDto;
import io.contexa.contexaiam.admin.web.studio.service.StudioActionService;
import io.contexa.contexaiam.admin.web.studio.service.StudioExplorerService;
import io.contexa.contexaiam.admin.web.studio.service.StudioVisualizerService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

import org.springframework.stereotype.Controller;

@Controller
@RequestMapping("/admin/studio")
@RequiredArgsConstructor
public class AuthorizationStudioController {

    private final StudioExplorerService explorerService;
    private final StudioVisualizerService visualizerService;
    private final StudioActionService actionService;

    @GetMapping
    public String studio(Model model) {
        model.addAttribute("activePage", "studio");
        return "admin/studio";
    }

    @GetMapping("/api/subject-details")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> getSubjectDetails(@RequestParam Long subjectId, @RequestParam String subjectType) {
        Map<String, Object> details = visualizerService.getSubjectDetails(subjectId, subjectType);
        return ResponseEntity.ok(details);
    }

    @GetMapping("/api/explorer-items")
    @ResponseBody
    public ResponseEntity<Map<String, List<ExplorerItemDto>>> getExplorerItems() {
        return ResponseEntity.ok(explorerService.getExplorerItems());
    }

    @GetMapping("/api/access-path")
    @ResponseBody
    public ResponseEntity<?> analyzeAccessPath(@RequestParam Long subjectId, @RequestParam String subjectType, @RequestParam Long permissionId) {
        return ResponseEntity.ok(visualizerService.analyzeAccessPath(subjectId, subjectType, permissionId));
    }

    @GetMapping("/api/access-path-graph")
    @ResponseBody
    public ResponseEntity<GraphDataDto> analyzeAccessPathAsGraph(@RequestParam Long subjectId, @RequestParam String subjectType, @RequestParam Long permissionId) {
        return ResponseEntity.ok(visualizerService.analyzeAccessPathAsGraph(subjectId, subjectType, permissionId));
    }

    @GetMapping("/api/effective-permissions")
    @ResponseBody
    public ResponseEntity<?> getEffectivePermissions(@RequestParam Long subjectId, @RequestParam String subjectType) {
        return ResponseEntity.ok(visualizerService.getEffectivePermissionsForSubject(subjectId, subjectType));
    }

    @PostMapping("/api/simulate")
    @ResponseBody
    public ResponseEntity<?> runSimulation(@RequestBody SimulationRequestDto request) {
        return ResponseEntity.ok(actionService.runPolicySimulation(request));
    }

    @PostMapping("/api/initiate-grant")
    @ResponseBody
    public ResponseEntity<?> initiateGrant(@RequestBody InitiateGrantRequestDto request) {
        return ResponseEntity.ok(actionService.initiateGrantWorkflow(request));
    }
}