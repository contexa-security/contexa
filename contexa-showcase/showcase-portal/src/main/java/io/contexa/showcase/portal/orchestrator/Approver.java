package io.contexa.showcase.portal.orchestrator;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.util.Map;
import java.util.Optional;

/**
 * The security administrator of a run, who reads a release request and approves it through the engine's own
 * administrator API (ADR-33). It is another employee of the IT administration with the engine's administrator role,
 * created for the run only when a release is asked for and removed with the run.
 */
public interface Approver {

    /** The engine's record of the block of a principal with its release request; empty when there is none. */
    Optional<BlockRecord> request(String username) throws IOException;

    /** Approves the release, so the engine allows the principal again; returns the HTTP status (200 when done). */
    int approve(long blockId, String reason) throws IOException;

    /**
     * docs/agent A3-8: quarantines, releases or removes what an agent (or one of its delegations, when given) learned,
     * through the engine's administrator API; the HTTP status and the engine's answer.
     */
    default LearningResult agentLearning(String agentId, String delegationId, String action, String reason)
            throws IOException {
        throw new UnsupportedOperationException("This approver cannot act on an agent's learning");
    }

    /**
     * docs/agent OC-1: records a delegation through the engine's delegation admin API, as the company's records state
     * it (an integration's import); the delegation's identifier the engine gave it.
     */
    default String recordDelegation(Map<String, Object> delegation) throws IOException {
        throw new UnsupportedOperationException("This approver cannot record a delegation");
    }

    /**
     * docs/agent OC-5: replays the sealed decision of the request through the engine's replay admin API; empty when the
     * decision was not sealed.
     */
    default Optional<JsonNode> replaySealed(String requestId, Map<String, Object> request) throws IOException {
        throw new UnsupportedOperationException("This approver cannot replay sealed decisions");
    }

    /**
     * docs/agent OC-2: puts the company's records into the engine through its company records admin API, as the
     * company's integration does; the answer says how many were kept.
     */
    default JsonNode putCompanyRecords(JsonNode records) throws IOException {
        throw new UnsupportedOperationException("This approver cannot put company records");
    }

    /** docs/agent OC-3: registers an agent through the engine's agent registration API; the answer, secrets included. */
    default JsonNode registerAgent(Map<String, Object> registration) throws IOException {
        throw new UnsupportedOperationException("This approver cannot register an agent");
    }

    /** docs/agent OC-3: removes an agent, its client, its tokens and its account through the same API. */
    default JsonNode removeAgent(String agentId) throws IOException {
        throw new UnsupportedOperationException("This approver cannot remove an agent");
    }

    /** The approver's name as the work database records the employee; null while the approver does not exist. */
    default String displayName() {
        return null;
    }

    /**
     * The block as the engine's administrator API returns it.
     *
     * @param username      the account the engine recorded the block on
     * @param reasoning     why the engine blocked the account
     * @param unblockReason the reason the principal gave for the release
     * @param mfaVerified   the principal passed the identity check before asking
     */
    record LearningResult(int status, JsonNode answer) {
    }

    record BlockRecord(long id, String username, String status, String reasoning, String blockedAt, String unblockReason,
                       Boolean mfaVerified, String unblockRequestedAt) {
    }
}
