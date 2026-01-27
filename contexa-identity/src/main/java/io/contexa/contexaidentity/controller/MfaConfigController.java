package io.contexa.contexaidentity.controller;

import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/mfa")
@RequiredArgsConstructor
public class MfaConfigController {

    private final AuthUrlProvider authUrlProvider;

    @GetMapping("/config")
    public ResponseEntity<Map<String, Object>> getEndpointConfig() {
        try {
            Map<String, Object> config = authUrlProvider.getAllUiPageUrls();
            return ResponseEntity.ok(config);
        } catch (Exception e) {
            log.error("Error retrieving endpoint configuration", e);
            return ResponseEntity.internalServerError()
                    .body(Map.of(
                            "error", "CONFIG_RETRIEVAL_FAILED",
                            "message", "Failed to retrieve endpoint configuration"
                    ));
        }
    }
}
