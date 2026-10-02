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
public class DownloadComparisonBodyContract extends AbstractComparisonBodyContract {

    public DownloadComparisonBodyContract(LabProperties properties) {
        super(properties);
    }

    @Override
    public boolean supports(String planKind) {
        return "DOCUMENT_DOWNLOAD_PAIR".equals(planKind);
    }

    @Override
    protected Set<String> acceptedFields() {
        return Set.of("purpose", "approvalId", "language", "commandId");
    }

    @Override
    protected boolean matchesOperation(ComparisonRequestPlan plan, JsonNode input) {
        var file = plan.fileRequest();
        return file != null && file.language() != null && file.commandId() != null
                && file.language().name().equals(input.path("language").textValue())
                && file.commandId().toString().equals(input.path("commandId").textValue());
    }
}
