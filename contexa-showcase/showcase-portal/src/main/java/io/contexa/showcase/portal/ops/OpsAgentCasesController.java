package io.contexa.showcase.portal.ops;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.portal.orchestrator.RunOrchestrator;
import io.contexa.showcase.portal.scenario.AgentTaskCatalog;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * docs/agent Agent중심-화면 AS-11, G-13: the agent cases of the catalog with the sender each is defined for and the hash of
 * its definition in force (the hash a run stores, so stored runs of the definition are found). The operator reads it to
 * count the benchmark's agent part again from the raw rows, independently of the benchmark service; operator port only.
 */
@RestController
@ConditionalOnProperty(prefix = "showcase.portal.ops", name = "port")
public class OpsAgentCasesController {

    public record Case(String key, String sender, String definitionSha256) {
    }

    private final AgentTaskCatalog catalog;
    private final ObjectMapper json;

    public OpsAgentCasesController(AgentTaskCatalog catalog, ObjectMapper json) {
        this.catalog = catalog;
        this.json = json;
    }

    @GetMapping("/ops/agent-tasks")
    public List<Case> cases() {
        return catalog.all().stream().map(task -> new Case(task.key(), task.task().sender().name(),
                RunOrchestrator.definitionSha256(json, task))).toList();
    }
}
