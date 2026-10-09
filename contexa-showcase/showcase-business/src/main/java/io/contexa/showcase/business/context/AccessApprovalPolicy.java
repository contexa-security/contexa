package io.contexa.showcase.business.context;

/**
 * The company's access approval rule of an operation that is not an export, as the business database holds it (table
 * company_policy, docs/showcase/데모-재설계.md Q-A4, approval Q-45): role grants, customer records and project
 * documents. Control C2's rules and control D's context provider read the same row and decide with this one method,
 * so the engine is told whether the company requires an approval exactly as the rule control applies it. A ticket
 * that covers the request is the approval record of these rules.
 *
 * @param accountManagerExempt the customer's account manager needs no approval
 * @param assignedExempt       an employee assigned to the project needs no approval
 * @param recentWorkDays       an employee who worked on the project within this many days needs no approval; null
 *                             when recent work does not exempt
 */
public record AccessApprovalPolicy(String policyKey, String description, boolean accountManagerExempt,
                                   boolean assignedExempt, Integer recentWorkDays) {

    /**
     * Whether the policy requires an approval for a request with these facts.
     *
     * @param daysWorkedRecently days with access to the project within {@link #recentWorkDays()}
     */
    public boolean requiresApproval(boolean accountManager, boolean assigned, int daysWorkedRecently) {
        boolean exemptAsAccountManager = accountManagerExempt && accountManager;
        boolean exemptAsAssigned = assignedExempt && assigned;
        boolean exemptByRecentWork = recentWorkDays != null && daysWorkedRecently > 0;
        return !(exemptAsAccountManager || exemptAsAssigned || exemptByRecentWork);
    }
}
