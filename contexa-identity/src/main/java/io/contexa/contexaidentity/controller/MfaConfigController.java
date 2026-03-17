package io.contexa.contexaidentity.controller;

import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.service.MfaFlowUrlRegistry;
import jakarta.servlet.http.HttpServletRequest;
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
    private final MfaFlowUrlRegistry mfaFlowUrlRegistry;
    private final MfaStateMachineIntegrator stateMachineIntegrator;

    @GetMapping("/config")
    public ResponseEntity<Map<String, Object>> getEndpointConfig(HttpServletRequest request) {
        try {
            AuthUrlProvider effectiveProvider = resolveFlowUrlProvider(request);
            Map<String, Object> config = effectiveProvider.getAllUiPageUrls();
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

    private AuthUrlProvider resolveFlowUrlProvider(HttpServletRequest request) {
        FactorContext ctx = stateMachineIntegrator.loadFactorContextFromRequest(request);
        if (ctx != null && ctx.getFlowTypeName() != null) {
            AuthUrlProvider flowProvider = mfaFlowUrlRegistry.getProvider(ctx.getFlowTypeName());
            if (flowProvider != null) {
                return flowProvider;
            }
        }
        return authUrlProvider;
    }
}
