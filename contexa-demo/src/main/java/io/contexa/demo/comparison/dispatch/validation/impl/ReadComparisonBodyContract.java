package io.contexa.demo.comparison.dispatch.validation.impl;

import com.fasterxml.jackson.databind.JsonNode;
import io.contexa.demo.comparison.dispatch.validation.support.AbstractComparisonBodyContract;
import io.contexa.demo.comparison.preparation.dto.ComparisonRequestPlan;
import io.contexa.demo.configuration.properties.LabProperties;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.util.Set;

@Component
@Profile({"baseline", "contexa"})
public class ReadComparisonBodyContract extends AbstractComparisonBodyContract {

    public ReadComparisonBodyContract(LabProperties properties) {
        super(properties);
    }

    @Override
    public boolean supports(String planKind) {
        return Set.of("DOCUMENT_READ_PAIR", "CUSTOMER_READ_PAIR").contains(planKind);
    }

    @Override
    protected Set<String> acceptedFields() {
        return Set.of("purpose", "approvalId");
    }

    @Override
    protected boolean matchesOperation(ComparisonRequestPlan plan, JsonNode input) {
        return plan.fileRequest() == null;
    }
}
