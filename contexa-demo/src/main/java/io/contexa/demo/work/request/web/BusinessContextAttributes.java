package io.contexa.demo.work.request.web;

import io.contexa.contexacommon.security.context.RequestSecurityContextAttributes;
import io.contexa.contexacommon.security.context.RequestSecurityContextAttributes.Field;
import io.contexa.demo.work.request.dto.WorkRequestSnapshot;
import jakarta.servlet.http.HttpServletRequest;

import java.util.UUID;

public final class BusinessContextAttributes {

    public static final String REQUEST_ID = "contexa.requestId";

    private BusinessContextAttributes() {
    }

    public static UUID requestId(HttpServletRequest request) {
        return UUID.fromString((String) request.getAttribute(REQUEST_ID));
    }

    public static void attach(HttpServletRequest request, WorkRequestSnapshot snapshot) {
        RequestSecurityContextAttributes.write(request, Field.RESOURCE_ID, snapshot.resourceFacts().id(), true);
        RequestSecurityContextAttributes.write(request, Field.RESOURCE_BUSINESS_LABEL,
                snapshot.resourceFacts().label(), true);
        RequestSecurityContextAttributes.write(request, Field.RESOURCE_SENSITIVITY,
                snapshot.resourceFacts().sensitivity(), true);
        RequestSecurityContextAttributes.write(request, Field.SENSITIVE_RESOURCE,
                "CONFIDENTIAL".equals(snapshot.resourceFacts().sensitivity()), true);
        // Project assignments are business facts, not a scalar resource-family classification.
        // The native context pipeline resolves resource families from the registered resource.
        request.setAttribute("currentActionFamily", snapshot.action());
        request.setAttribute("expectedActionFamilies", snapshot.resourceFacts().allowedActions());
    }
}
