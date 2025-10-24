package io.contexa.contexaiam.aiam.protocol.request;

import io.contexa.contexaiam.aiam.protocol.context.PolicyContext;
import io.contexa.contexacommon.domain.request.IAMRequest;

public class PolicyGenerationRequest extends IAMRequest<PolicyContext> {

    private final String naturalLanguageQuery;
    private final PolicyGenerationItem.AvailableItems availableItems;

    public PolicyGenerationRequest(String naturalLanguageQuery, PolicyGenerationItem.AvailableItems availableItems) {
        super(null, null);
        this.naturalLanguageQuery = naturalLanguageQuery;
        this.availableItems = availableItems;
    }

    public PolicyGenerationRequest(PolicyContext context, String operation, String naturalLanguageQuery,
                                   PolicyGenerationItem.AvailableItems availableItems) {
        super(context, operation);
        this.naturalLanguageQuery = naturalLanguageQuery;
        this.availableItems = availableItems;
    }

    public String getNaturalLanguageQuery() {
        return naturalLanguageQuery;
    }

    public PolicyGenerationItem.AvailableItems getAvailableItems() {
        return availableItems;
    }
}
