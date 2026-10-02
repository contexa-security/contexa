package io.contexa.demo.comparison.dispatch.validation.impl;

import com.fasterxml.jackson.databind.JsonNode;
import io.contexa.demo.comparison.dispatch.validation.support.AbstractComparisonBodyContract;
import io.contexa.demo.comparison.preparation.dto.ComparisonRequestPlan;
import io.contexa.demo.configuration.properties.LabProperties;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import java.util.Set;
import java.util.stream.StreamSupport;

@Component
@Profile({"baseline", "contexa"})
public class ExportComparisonBodyContract extends AbstractComparisonBodyContract {

    public ExportComparisonBodyContract(LabProperties properties) {
        super(properties);
    }

    @Override
    public boolean supports(String planKind) {
        return "BUSINESS_EXPORT_PAIR".equals(planKind);
    }

    @Override
    protected Set<String> acceptedFields() {
        return Set.of("purpose", "approvalId", "language", "commandId", "resourceType", "targetIds");
    }

    @Override
    protected boolean matchesOperation(ComparisonRequestPlan plan, JsonNode input) {
        var file = plan.fileRequest();
        var selection = plan.exportSelection();
        return file != null && selection != null && input.path("targetIds").isArray()
                && file.language().name().equals(input.path("language").textValue())
                && file.commandId().toString().equals(input.path("commandId").textValue())
                && selection.resourceType().name().equals(input.path("resourceType").textValue())
                && selection.targetIds().equals(StreamSupport.stream(input.path("targetIds").spliterator(), false)
                        .map(JsonNode::textValue).toList());
    }
}
