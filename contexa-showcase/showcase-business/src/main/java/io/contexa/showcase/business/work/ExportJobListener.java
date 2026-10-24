package io.contexa.showcase.business.work;

import java.util.UUID;

/**
 * Told when an export job has ended and its delivered items are recorded in {@code export_job} (docs/agent OC-2):
 * control D reports what it delivered to Contexa's company records, as an adopter reports usage under approvals. The
 * plain controls have none.
 */
public interface ExportJobListener {

    /** The job ended (completed or interrupted); its row holds the final delivered items. */
    void finished(UUID jobId);
}
