package io.contexa.showcase.workload.contexa.context;

import io.contexa.contexacore.autonomous.context.enricher.DelegationRecord;
import io.contexa.contexacore.autonomous.context.enricher.DelegationRecordLookup;
import io.contexa.contexacore.autonomous.context.enricher.DelegationRecordQuery;
import io.contexa.showcase.business.context.AgentDelegations;

import java.time.Instant;
import java.util.Optional;

/**
 * The delegation of record of an agent request, read from the business database through the engine's public delegation
 * record lookup (docs/agent A7-0, A1-4). The company records what the person delegated; the engine narrows what the
 * request's token or session stated to it. A revoked delegation is returned as one that ended when it began, so its
 * end is a fact the decision weighs.
 */
public class ShowcaseDelegationRecordLookup implements DelegationRecordLookup {

    private final AgentDelegations delegations;

    public ShowcaseDelegationRecordLookup(AgentDelegations delegations) {
        this.delegations = delegations;
    }

    @Override
    public Optional<DelegationRecord> find(DelegationRecordQuery query) {
        if (query == null) {
            return Optional.empty();
        }
        return delegations.find(query.delegatorId(), query.agentId(), query.delegationId())
                .map(found -> new DelegationRecord(
                        found.delegationKey(),
                        found.delegatorUsername(),
                        found.agentId(),
                        found.objectiveId(),
                        found.objectiveFamily(),
                        found.summary(),
                        found.operations(),
                        found.resources(),
                        found.approvalRequired(),
                        null,
                        null,
                        endOf(found),
                        found.recordedBy(),
                        found.recordedAt()));
    }

    private static Instant endOf(AgentDelegations.Delegation found) {
        return found.revoked() ? found.validFrom() : found.expiresAt();
    }
}
