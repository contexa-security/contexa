package io.contexa.showcase.portal.ops;

import io.contexa.showcase.portal.orchestrator.OpsAdministrator;
import io.contexa.showcase.portal.orchestrator.WorkloadAdmin;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.util.List;
import java.util.Map;

/**
 * docs/agent B4: a check of control D's OpenID AuthZEN evaluation API from outside (operator port): an enforcement
 * point registered for the check asks the evaluations the operator gives and reads the metadata; it is removed after.
 * Control D answers only when its {@code contexa.security.zerotrust.authzen.enabled} is on.
 */
@RestController
@ConditionalOnProperty(prefix = "showcase.portal.ops", name = "port")
public class AuthzenOpsController {

    private static final int MAX_CALLS = 10;

    private final ObjectProvider<WorkloadAdmin> admin;

    public AuthzenOpsController(ObjectProvider<WorkloadAdmin> admin) {
        this.admin = admin;
    }

    /**
     * @param calls    the calls, each {@code {endpoint: evaluation|evaluations, body, requestId?}}
     * @param basePath control D's AuthZEN base path
     */
    @PostMapping("/ops/authzen-checks")
    public ResponseEntity<Object> check(@RequestBody List<Map<String, Object>> calls,
                                        @RequestParam(name = "basePath", defaultValue = "/contexa/authzen")
                                        String basePath) throws IOException {
        WorkloadAdmin workloadAdmin = admin.getIfAvailable();
        if (workloadAdmin == null) {
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).build();
        }
        if (calls == null || calls.isEmpty() || calls.size() > MAX_CALLS || !basePath.matches("/[a-z0-9/-]{1,60}")) {
            return ResponseEntity.badRequest().build();
        }
        try (OpsAdministrator operator = workloadAdmin.opsAdministrator()) {
            return ResponseEntity.ok(operator.authzenCheck(basePath, calls));
        }
    }
}
