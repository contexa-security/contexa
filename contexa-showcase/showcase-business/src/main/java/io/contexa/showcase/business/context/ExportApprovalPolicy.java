package io.contexa.showcase.business.context;

/**
 * The company's export approval policy as the business database holds it (table company_policy, docs/showcase/
 * 데모-재설계.md H-15). Control C2's rules and control D's context provider read the same row and decide with this one
 * method, so the engine is told whether the company requires an approval exactly as the rule control applies it, and
 * neither side keeps a copy of the policy in code.
 *
 * @param assignedExportLimit    an employee assigned to the project exports up to this many items without approval
 * @param ticketAndOncallExempt  an export covered by a ticket while the requester is on call needs no approval
 */
public record ExportApprovalPolicy(String policyKey, String description, int assignedExportLimit,
                                   boolean ticketAndOncallExempt) {

    /** Whether the policy requires an approval for an export with these facts. */
    public boolean requiresApproval(boolean assigned, int items, boolean ticketCovered, boolean onCall) {
        boolean exemptByTicket = ticketAndOncallExempt && ticketCovered && onCall;
        boolean exemptByAssignment = assigned && items <= assignedExportLimit;
        return !(exemptByTicket || exemptByAssignment);
    }
}
