package io.contexa.showcase.portal.hook;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/** Operator API of the first screen's replay, on the operator port only (OpsPortConfiguration). */
@RestController
@ConditionalOnProperty(prefix = "showcase.portal.ops", name = "port")
public class HookOpsController {

    public record DesignationRequest(String attackerRunId, String ownerRunId) {
    }

    private final HookViews hook;
    private final HookStore store;

    public HookOpsController(HookViews hook, HookStore store) {
        this.hook = hook;
        this.store = store;
    }

    /** The designated runs and, once both are, the replay with when its texts reach the retention period. */
    @GetMapping("/ops/hook")
    public Map<String, Object> status() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("designated", store.designated());
        status.put("view", hook.view().orElse(null));
        return status;
    }

    @PostMapping("/ops/hook")
    public ResponseEntity<Object> designate(@RequestBody DesignationRequest request) {
        Optional<HookViews.Refusal> refused = request == null
                ? Optional.of(new HookViews.Refusal("ATTACKER", "UNKNOWN_RUN"))
                : hook.designate(request.attackerRunId(), request.ownerRunId());
        if (refused.isPresent()) {
            return ResponseEntity.badRequest().body(refused.get());
        }
        return ResponseEntity.ok(status());
    }
}
