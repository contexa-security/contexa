package io.contexa.showcase.portal.ops;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/** docs/agent Agent중심-화면 AC-9: the operator's budget page; the operator port only. */
@RestController
@ConditionalOnProperty(prefix = "showcase.portal.ops", name = "port")
public class OpsBudgetController {

    private final OpsBudget budget;

    public OpsBudgetController(OpsBudget budget) {
        this.budget = budget;
    }

    @GetMapping(value = "/ops/budget", produces = "text/html;charset=UTF-8")
    public ResponseEntity<String> page() {
        return ResponseEntity.ok().contentType(MediaType.parseMediaType("text/html;charset=UTF-8")).body(budget.page());
    }
}
