package io.contexa.showcase.portal.hook;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/** Visitor API of the first screen's replay; 404 until the operator designated its two runs. */
@RestController
public class HookController {

    private final HookViews hook;

    public HookController(HookViews hook) {
        this.hook = hook;
    }

    @GetMapping("/api/hook")
    public ResponseEntity<HookViews.View> hook() {
        return ResponseEntity.of(hook.view());
    }
}
