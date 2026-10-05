package io.contexa.showcase.business.context;

import io.contexa.showcase.business.work.BusinessOperation;

import java.util.EnumSet;
import java.util.Set;

/**
 * Which company facts are looked up for each operation, the same for control C2's rules and control D's context
 * provider (deck p.18: "no information gap enters the result"; P1-BE-04). Each side's test records the lookups it
 * makes and compares them with this plan, so both sides see exactly the same facts. A rule may ignore a fact it
 * looked up; it never sees one the engine does not, and the reverse.
 */
public final class LookupPlan {

    public enum LookupFunction {
        PROJECT_ASSIGNED, APPROVAL_EXISTS, TICKET_COVERS, ONCALL_HAS, HISTORY_DAYS, CUSTOMER_OWNER, CLAIMED_TICKET,
        NETWORK_CONTEXT
    }

    private LookupPlan() {
    }

    /** The plan of a request: the operation's lookups, plus the check of a ticket the requester names. */
    public static Set<LookupFunction> forRequest(BusinessOperation operation, boolean claimsTicket) {
        Set<LookupFunction> plan = EnumSet.noneOf(LookupFunction.class);
        plan.addAll(forOperation(operation));
        if (claimsTicket && (operation == BusinessOperation.EXPORT || operation == BusinessOperation.EXPORT_STREAM)) {
            plan.add(LookupFunction.CLAIMED_TICKET);
        }
        return plan;
    }

    public static Set<LookupFunction> forOperation(BusinessOperation operation) {
        return switch (operation) {
            case EXPORT, EXPORT_STREAM -> EnumSet.of(LookupFunction.PROJECT_ASSIGNED, LookupFunction.APPROVAL_EXISTS,
                    LookupFunction.TICKET_COVERS, LookupFunction.ONCALL_HAS, LookupFunction.HISTORY_DAYS,
                    LookupFunction.NETWORK_CONTEXT);
            case DOCUMENT_READ, DOCUMENT_DOWNLOAD -> EnumSet.of(LookupFunction.PROJECT_ASSIGNED,
                    LookupFunction.TICKET_COVERS, LookupFunction.HISTORY_DAYS, LookupFunction.NETWORK_CONTEXT);
            case CUSTOMER_READ -> EnumSet.of(LookupFunction.CUSTOMER_OWNER, LookupFunction.TICKET_COVERS,
                    LookupFunction.NETWORK_CONTEXT);
            case ROLE_GRANT -> EnumSet.of(LookupFunction.TICKET_COVERS, LookupFunction.NETWORK_CONTEXT);
            case PROJECT_LIST -> EnumSet.noneOf(LookupFunction.class);
        };
    }
}
