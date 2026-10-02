package io.contexa.demo.comparison.dispatch.validation;

import com.fasterxml.jackson.databind.JsonNode;
import io.contexa.demo.comparison.preparation.dto.ComparisonRequestPlan;

public interface ComparisonBodyContract {

    boolean supports(String planKind);

    void verify(ComparisonRequestPlan plan, JsonNode input);
}
