package io.contexa.showcase.portal.menu;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Predicate;

/**
 * docs/agent Agent중심-화면 AC-4a: the operator's side of the agent menu (operator port only): what the table holds and
 * how the latest days of the job went, and a refresh at once, in the background, one at a time.
 */
@RestController
@ConditionalOnProperty(prefix = "showcase.portal.ops", name = "port")
public class AgentMenuOpsController {

    private static final Logger log = LoggerFactory.getLogger(AgentMenuOpsController.class);

    private final ObjectProvider<AgentMenuStore> store;
    private final ObjectProvider<AgentMenuJob> job;
    private final ObjectProvider<ExecutorService> executor;
    private final AtomicBoolean refreshing = new AtomicBoolean();

    /** The menu's parts exist only where control D is configured; without it the endpoints answer not found. */
    public AgentMenuOpsController(ObjectProvider<AgentMenuStore> store, ObjectProvider<AgentMenuJob> job,
                                  @Qualifier("agentMenuExecutor") ObjectProvider<ExecutorService> executor) {
        this.store = store;
        this.job = job;
        this.executor = executor;
    }

    @GetMapping("/ops/agent-menu")
    public ResponseEntity<Map<String, Object>> status() {
        AgentMenuStore menu = store.getIfAvailable();
        if (menu == null) {
            return ResponseEntity.notFound().build();
        }
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("refreshing", refreshing.get());
        status.put("combinations", AgentMenu.combos().size());
        status.put("entries", menu.all());
        status.put("jobs", menu.jobs(14));
        return ResponseEntity.ok(status);
    }

    /**
     * Starts a refresh of the whole table, or of one case's combinations ({@code case}, e.g. ED1: the editable case's
     * fifty-four), refused while one is going on.
     */
    @PostMapping("/ops/agent-menu/refresh")
    public ResponseEntity<Map<String, Object>> refresh(@RequestParam(name = "case", required = false) String caseKey) {
        Predicate<AgentMenu.Combo> only = combo -> caseKey == null || caseKey.equals(combo.caseKey());
        if (AgentMenu.combos().stream().noneMatch(only)) {
            return ResponseEntity.badRequest().build();
        }
        AgentMenuJob menuJob = job.getIfAvailable();
        ExecutorService background = executor.getIfAvailable();
        if (menuJob == null || background == null) {
            return ResponseEntity.notFound().build();
        }
        if (!refreshing.compareAndSet(false, true)) {
            return ResponseEntity.status(409).body(Map.of("refreshing", true));
        }
        background.submit(() -> {
            try {
                AgentMenuJob.Result result = menuJob.refresh(only);
                log.info("The agent menu was refreshed: {}", result);
            } catch (RuntimeException e) {
                log.error("The agent menu's refresh failed", e);
            } finally {
                refreshing.set(false);
            }
        });
        return ResponseEntity.accepted().body(Map.of("refreshing", true,
                "combinations", AgentMenu.combos().stream().filter(only).count()));
    }
}
