package io.contexa.demo.comparison.dispatch.validation.support;

import com.fasterxml.jackson.databind.JsonNode;
import io.contexa.demo.comparison.dispatch.validation.ComparisonBodyContract;
import io.contexa.demo.comparison.preparation.dto.ComparisonRequestPlan;
import io.contexa.demo.configuration.properties.LabProperties;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import java.util.Set;

public abstract class AbstractComparisonBodyContract implements ComparisonBodyContract {

    private final String arm;

    protected AbstractComparisonBodyContract(LabProperties properties) {
        this.arm = properties.role();
    }

    @Override
    public final void verify(ComparisonRequestPlan plan, JsonNode input) {
        if (input == null || !input.isObject() || !input.path("purpose").isTextual()
                || !plan.purpose().name().equals(input.path("purpose").textValue())
                || !matchesApproval(plan, input)
                || !matchesOperation(plan, input)) {
            throw mismatch();
        }
        var fields = input.fieldNames();
        Set<String> accepted = acceptedFields();
        while (fields.hasNext()) {
            if (!accepted.contains(fields.next())) {
                throw mismatch();
            }
        }
    }

    protected abstract Set<String> acceptedFields();

    protected abstract boolean matchesOperation(ComparisonRequestPlan plan, JsonNode input);

    protected boolean matchesApproval(ComparisonRequestPlan plan, JsonNode input) {
        var approval = plan.approvalFor(arm);
        return approval == null ? !input.has("approvalId") || input.get("approvalId").isNull()
                : approval.toString().equals(input.path("approvalId").textValue());
    }

    private ResponseStatusException mismatch() {
        return new ResponseStatusException(HttpStatus.UNPROCESSABLE_ENTITY, "REQUEST_PLAN_MISMATCH");
    }
}
