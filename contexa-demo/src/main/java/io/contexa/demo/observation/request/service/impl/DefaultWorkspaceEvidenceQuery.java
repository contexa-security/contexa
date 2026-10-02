package io.contexa.demo.observation.request.service.impl;

import io.contexa.demo.observation.request.dto.RequestEvidenceView;
import io.contexa.demo.observation.request.service.RequestEvidenceQuery;
import io.contexa.demo.observation.request.service.WorkspaceEvidenceQuery;
import io.contexa.demo.workspace.evidence.service.WorkspaceEvidenceScope;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import java.util.Map;
import java.util.UUID;

public class DefaultWorkspaceEvidenceQuery implements WorkspaceEvidenceQuery {

    private final Map<String, RequestEvidenceQuery> arms;
    private final WorkspaceEvidenceScope scope;

    public DefaultWorkspaceEvidenceQuery(Map<String, RequestEvidenceQuery> arms, WorkspaceEvidenceScope scope) {
        this.arms = Map.copyOf(arms);
        this.scope = scope;
    }

    @Override
    public RequestEvidenceView find(String arm, UUID requestId, UUID visitorId) {
        RequestEvidenceQuery query = arms.get(arm);
        if (query == null) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        }
        return scope.withOwner(visitorId, () -> query.find(requestId, visitorId));
    }
}
