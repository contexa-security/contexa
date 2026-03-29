package io.contexa.springbootstartercontexa.web;

import io.contexa.springbootstartercontexa.service.SecurityTestEvidenceService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.annotation.StreamingResponseBody;

import java.util.Map;

@RestController
@RequestMapping({"/api/security-test/evidence", "/admin/api/security-test/evidence"})
@RequiredArgsConstructor
public class SecurityTestEvidenceController {

    private final SecurityTestEvidenceService securityTestEvidenceService;

    @GetMapping("/current")
    public ResponseEntity<Map<String, Object>> getCurrentEvidence() {
        return ResponseEntity.ok(securityTestEvidenceService.getCurrentEvidence(currentUserId()));
    }

    @GetMapping("/{requestId}")
    public ResponseEntity<Map<String, Object>> getEvidence(@PathVariable String requestId) {
        return ResponseEntity.ok(securityTestEvidenceService.getEvidence(currentUserId(), requestId));
    }

    @GetMapping("/{requestId}/export")
    public ResponseEntity<Map<String, Object>> exportEvidence(@PathVariable String requestId) {
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"security-test-evidence-" + requestId + ".json\"")
                .contentType(MediaType.APPLICATION_JSON)
                .body(securityTestEvidenceService.exportEvidence(currentUserId(), requestId));
    }

    @GetMapping(value = {"/{requestId}/stream", "/stream/current"}, produces = MediaType.APPLICATION_NDJSON_VALUE)
    public ResponseEntity<StreamingResponseBody> streamEvidence(@PathVariable(required = false) String requestId) {
        StreamingResponseBody stream = securityTestEvidenceService.streamEvidence(currentUserId(), requestId);
        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_NDJSON)
                .body(stream);
    }

    private String currentUserId() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || authentication.getName() == null) {
            return "anonymous";
        }
        return authentication.getName();
    }
}
