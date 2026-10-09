package io.contexa.showcase.portal.orchestrator;

import java.io.IOException;
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
    record BlockRecord(long id, String username, String status, String reasoning, String blockedAt, String unblockReason,
                       Boolean mfaVerified, String unblockRequestedAt) {
    }
}
