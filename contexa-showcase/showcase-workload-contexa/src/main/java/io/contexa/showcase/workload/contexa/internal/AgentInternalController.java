package io.contexa.showcase.workload.contexa.internal;

import io.contexa.showcase.workload.contexa.principal.RunAgentService;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The agents of a run (docs/agent A7-0), called only by the portal orchestrator with a signed internal context, as
 * the rest of D's management API.
 */
@RestController
public class AgentInternalController {

    /**
     * @param accountPassword the password of the agent's own account (a session agent); null for an agent with tokens
     * @param accountRoleKey  the company role of the account
     */
    public record AgentRequest(String agentId, String displayName, String sponsor, String clientId, String clientSecret,
                               List<String> scopes, String accountPassword, String accountRoleKey) {
    }

    private final RunAgentService agents;

    public AgentInternalController(RunAgentService agents) {
        this.agents = agents;
    }

    @PostMapping("/internal/runs/{runId}/agents")
    public Map<String, Object> register(@PathVariable("runId") String runId, @RequestBody AgentRequest request) {
        agents.register(new RunAgentService.Agent(runId, request.agentId(), request.displayName(), request.sponsor(),
                request.clientId(), request.clientSecret(), request.scopes(), request.accountPassword(),
                request.accountRoleKey()));
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("agentId", request.agentId());
        result.put("clientId", request.clientId());
        result.put("account", request.accountPassword() != null && !request.accountPassword().isBlank());
        return result;
    }

    @DeleteMapping("/internal/runs/{runId}/agents/{agentId}")
    public Map<String, Object> remove(@PathVariable("runId") String runId, @PathVariable("agentId") String agentId,
                                      @RequestParam("clientId") String clientId) {
        agents.remove(agentId, clientId);
        return Map.of("agentId", agentId, "removed", true);
    }
}
