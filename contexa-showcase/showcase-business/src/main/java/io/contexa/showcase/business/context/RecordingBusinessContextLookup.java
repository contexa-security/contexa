package io.contexa.showcase.business.context;

import io.contexa.showcase.business.context.LookupPlan.LookupFunction;
import io.contexa.showcase.business.work.BusinessOperation;

import java.time.Instant;
import java.util.EnumSet;
import java.util.Optional;
import java.util.Set;

/**
 * Delegating {@link BusinessContextLookup} that records which lookup functions were called, for the parity checks
 * of {@link LookupPlan}.
 */
public final class RecordingBusinessContextLookup implements BusinessContextLookup {

    private final BusinessContextLookup delegate;
    private final Set<LookupFunction> called = EnumSet.noneOf(LookupFunction.class);

    public RecordingBusinessContextLookup(BusinessContextLookup delegate) {
        this.delegate = delegate;
    }

    public synchronized Set<LookupFunction> called() {
        return EnumSet.copyOf(called.isEmpty() ? EnumSet.noneOf(LookupFunction.class) : called);
    }

    private synchronized void record(LookupFunction function) {
        called.add(function);
    }

    @Override
    public Optional<RunPrincipal> principal(String username) {
        return delegate.principal(username);
    }

    @Override
    public TicketCoverage ticketCovers(String username, String projectKey, BusinessOperation operation, Instant at) {
        record(LookupFunction.TICKET_COVERS);
        return delegate.ticketCovers(username, projectKey, operation, at);
    }

    @Override
    public OncallStatus oncallHas(String username, Instant at) {
        record(LookupFunction.ONCALL_HAS);
        return delegate.oncallHas(username, at);
    }

    @Override
    public AssignmentStatus projectAssigned(String username, String projectKey, Instant at) {
        record(LookupFunction.PROJECT_ASSIGNED);
        return delegate.projectAssigned(username, projectKey, at);
    }

    @Override
    public ApprovalCoverage approvalExists(String username, String projectKey, int items, Instant at) {
        record(LookupFunction.APPROVAL_EXISTS);
        return delegate.approvalExists(username, projectKey, items, at);
    }

    @Override
    public ExportApprovalPolicy exportApprovalPolicy() {
        record(LookupFunction.EXPORT_POLICY);
        return delegate.exportApprovalPolicy();
    }

    @Override
    public AccessApprovalPolicy accessApprovalPolicy(BusinessOperation operation) {
        record(LookupFunction.ACCESS_POLICY);
        return delegate.accessApprovalPolicy(operation);
    }

    @Override
    public AccessHistory historyDays(String username, String projectKey, Instant at, int windowDays) {
        record(LookupFunction.HISTORY_DAYS);
        return delegate.historyDays(username, projectKey, at, windowDays);
    }

    @Override
    public CustomerOwnership customerOwner(String username, String customerKey) {
        record(LookupFunction.CUSTOMER_OWNER);
        return delegate.customerOwner(username, customerKey);
    }

    @Override
    public ClaimCheck claimedTicket(String username, String ticketKey, String projectKey, BusinessOperation operation,
                                    Instant at) {
        record(LookupFunction.CLAIMED_TICKET);
        return delegate.claimedTicket(username, ticketKey, projectKey, operation, at);
    }

    @Override
    public NetworkContext networkContext(String username, String clientIp, Instant at) {
        record(LookupFunction.NETWORK_CONTEXT);
        return delegate.networkContext(username, clientIp, at);
    }
}
