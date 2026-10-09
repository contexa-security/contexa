package io.contexa.showcase.workload.plain.rules;

import io.contexa.showcase.business.work.BusinessOperation;

import java.time.Instant;

/**
 * What a business request asks for, read from its path and query before the operation runs: the operation, the
 * target key, the project the target belongs to, the item count and the company time.
 *
 * @param projectKey    project of the target; for a customer, the project the customer bought; null for project lists
 * @param claimedTicket a ticket the requester names in the request (deck A8), or null; a claim is checked, never
 *                      trusted
 * @param clientIp      the requester's address as the signed internal context gives it
 */
public record RequestFacts(BusinessOperation operation, String username, String targetKey, String projectKey,
                           Integer items, Instant companyTime, String claimedTicket, String clientIp) {

    public RequestFacts(BusinessOperation operation, String username, String targetKey, String projectKey, int items,
                        Instant companyTime) {
        this(operation, username, targetKey, projectKey, items, companyTime, null, null);
    }

    public RequestFacts(BusinessOperation operation, String username, String targetKey, String projectKey, int items,
                        Instant companyTime, String claimedTicket) {
        this(operation, username, targetKey, projectKey, items, companyTime, claimedTicket, null);
    }
}
