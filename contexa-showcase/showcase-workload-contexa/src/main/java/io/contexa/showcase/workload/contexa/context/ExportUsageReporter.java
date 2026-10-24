package io.contexa.showcase.workload.contexa.context;

import io.contexa.contexacore.autonomous.company.CompanyRecordSet;
import io.contexa.contexacore.autonomous.company.CompanyRecordSet.Usage;
import io.contexa.contexacore.autonomous.company.CompanyRecordStore;
import io.contexa.showcase.business.work.ExportJobListener;
import io.contexa.showcase.business.work.WorkDatabase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;

import java.time.Clock;
import java.util.List;
import java.util.UUID;

/**
 * Control D reports what each export delivered to Contexa's company records (docs/agent OC-2), as an application
 * reports its usage under approvals through {@link CompanyRecordStore}: the person, the project, the delivered items
 * and the company time of the export. Contexa counts them against the person's approvals that report usage. A failed
 * report is logged and leaves the export as it is.
 */
public class ExportUsageReporter implements ExportJobListener {

    private static final Logger log = LoggerFactory.getLogger(ExportUsageReporter.class);

    /** Who the usage records say put them. */
    static final String REPORTER = "showcase-control-d";

    private final WorkDatabase database;
    private final CompanyRecordStore records;
    private final Clock clock;

    public ExportUsageReporter(WorkDatabase database, CompanyRecordStore records, Clock clock) {
        this.database = database;
        this.records = records;
        this.clock = clock;
    }

    @Override
    public void finished(UUID jobId) {
        try {
            List<Usage> usage = database.jdbc().query("""
                            select username, project_key, delivered_items, company_at from export_job
                             where job_id = :job and company_at is not null""",
                    new MapSqlParameterSource("job", jobId),
                    (rs, n) -> new Usage(jobId.toString(), rs.getString(1), rs.getString(2), rs.getInt(3),
                            rs.getTimestamp(4).toInstant()));
            if (usage.isEmpty()) {
                return;
            }
            records.put(null, new CompanyRecordSet(null, null, null, null, null, null, null, null, usage, null, null),
                    REPORTER, clock.instant());
        } catch (RuntimeException e) {
            log.error("The usage of export job {} was not reported to the company records", jobId, e);
        }
    }
}
