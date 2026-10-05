package io.contexa.showcase.business.work;

import io.contexa.showcase.business.work.BusinessViews.CustomerView;
import io.contexa.showcase.business.work.BusinessViews.DocumentFile;
import io.contexa.showcase.business.work.BusinessViews.DocumentView;
import io.contexa.showcase.business.work.BusinessViews.ExportResult;
import io.contexa.showcase.business.work.BusinessViews.ExportStream;
import io.contexa.showcase.business.work.BusinessViews.ExportedDocument;
import io.contexa.showcase.business.work.BusinessViews.ProjectSummary;
import io.contexa.showcase.business.work.BusinessViews.RoleGrantResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.web.servlet.mvc.method.annotation.StreamingResponseBody;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;

/**
 * The business behaviour of the virtual company, identical in every control. It records the outcome of every
 * export in {@code export_job}: requested and delivered items, and the manifest of what left the company.
 */
public class BusinessService implements BusinessOperations {

    private static final Logger log = LoggerFactory.getLogger(BusinessService.class);

    private final WorkDatabase database;
    private final Clock clock;
    private final int rowsPerTick;
    private final Duration tick;

    public BusinessService(WorkDatabase database, Clock clock, int rowsPerTick, Duration tick) {
        this.database = database;
        this.clock = clock;
        this.rowsPerTick = rowsPerTick;
        this.tick = tick;
    }

    @Override
    public List<ProjectSummary> listProjects(BusinessRequest request) {
        return database.jdbc().query("""
                        select p.project_key, p.display_name, p.program, p.sensitivity, count(d.document_key)
                          from project p left join document d on d.project_key = p.project_key
                         group by p.project_key, p.display_name, p.program, p.sensitivity
                         order by p.project_key""",
                new MapSqlParameterSource(),
                (rs, n) -> new ProjectSummary(rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(4),
                        rs.getInt(5)));
    }

    @Override
    public DocumentView readDocument(BusinessRequest request, String documentKey) {
        return database.jdbc().query("""
                        select document_key, project_key, document_type, title, revision, sensitivity, size_bytes, body
                          from document where document_key = :key""",
                new MapSqlParameterSource("key", documentKey),
                (rs, n) -> new DocumentView(rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(4),
                        rs.getString(5), rs.getString(6), rs.getInt(7), rs.getString(8)))
                .stream().findFirst()
                .orElseThrow(() -> new BusinessNotFoundException("document", documentKey));
    }

    @Override
    public DocumentFile downloadDocument(BusinessRequest request, String documentKey) {
        DocumentView document = readDocument(request, documentKey);
        String content = document.title() + "\nrevision " + document.revision() + "\nproject "
                + document.projectKey() + "\nsensitivity " + document.sensitivity() + "\n\n" + document.body() + "\n";
        return new DocumentFile(document.documentKey() + ".txt", "text/plain",
                content.getBytes(StandardCharsets.UTF_8), document.projectKey());
    }

    @Override
    public ExportResult exportDocuments(BusinessRequest request, String projectKey, int items) {
        requireProject(projectKey);
        UUID jobId = UUID.randomUUID();
        insertJob(jobId, request, projectKey, "SYNC", items);
        List<ExportedDocument> documents = selectDocuments(projectKey, items);
        String manifest = manifest(documents.stream().map(ExportedDocument::documentKey).toList());
        finishJob(jobId, documents.size(), "COMPLETED", manifest);
        return new ExportResult(jobId, projectKey, items, documents.size(), manifest, documents);
    }

    @Override
    public ExportStream openExportStream(BusinessRequest request, String projectKey, int items) {
        requireProject(projectKey);
        UUID jobId = UUID.randomUUID();
        insertJob(jobId, request, projectKey, "STREAM", items);
        List<ExportedDocument> documents = selectDocuments(projectKey, items);
        StreamingResponseBody body = out -> stream(jobId, documents, out);
        return new ExportStream(jobId, projectKey, items, documents.size(), body);
    }

    @Override
    public RoleGrantResult grantRole(BusinessRequest request, String projectKey, String grantee,
                                     String responsibility) {
        requireProject(projectKey);
        Integer employees = database.jdbc().queryForObject("select count(*) from employee where employee_key = :key",
                new MapSqlParameterSource("key", grantee), Integer.class);
        if (employees == null || employees == 0) {
            throw new BusinessNotFoundException("employee", grantee);
        }
        UUID grantId = UUID.randomUUID();
        database.jdbc().update("""
                        insert into role_grant (grant_id, run_id, request_id, granted_by, grantee, project_key,
                                                responsibility, granted_at)
                        values (:id, :run, :request, :by, :grantee, :project, :responsibility, :at)""",
                new MapSqlParameterSource("id", grantId).addValue("run", request.runId())
                        .addValue("request", request.requestId()).addValue("by", request.username())
                        .addValue("grantee", grantee).addValue("project", projectKey)
                        .addValue("responsibility", responsibility)
                        .addValue("at", Timestamp.from(request.companyTime())));
        return new RoleGrantResult(grantId, grantee, projectKey, responsibility, request.companyTime());
    }

    @Override
    public CustomerView readCustomer(BusinessRequest request, String customerKey) {
        return database.jdbc().query("""
                        select customer_key, display_name, region, account_manager, project_key
                          from customer where customer_key = :key""",
                new MapSqlParameterSource("key", customerKey),
                (rs, n) -> new CustomerView(rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(4),
                        rs.getString(5)))
                .stream().findFirst()
                .orElseThrow(() -> new BusinessNotFoundException("customer", customerKey));
    }

    /** Writes one document per line; an engine cut or a closed connection ends the job as INTERRUPTED. */
    private void stream(UUID jobId, List<ExportedDocument> documents, OutputStream out) throws IOException {
        int delivered = 0;
        MessageDigest digest = sha256();
        try {
            for (ExportedDocument document : documents) {
                String line = "{\"documentKey\":\"" + document.documentKey() + "\",\"title\":\""
                        + document.title() + "\",\"revision\":\"" + document.revision() + "\"}\n";
                out.write(line.getBytes(StandardCharsets.UTF_8));
                digest.update((document.documentKey() + "\n").getBytes(StandardCharsets.UTF_8));
                delivered++;
                if (delivered % rowsPerTick == 0) {
                    out.flush();
                    sleep();
                }
            }
            out.flush();
            finishJob(jobId, delivered, "COMPLETED", HexFormat.of().formatHex(digest.digest()));
        } catch (IOException e) {
            finishJob(jobId, delivered, "INTERRUPTED", null);
            throw e;
        } catch (RuntimeException e) {
            log.error("Streaming export failed: jobId={}", jobId, e);
            finishJob(jobId, delivered, "INTERRUPTED", null);
            throw e;
        }
    }

    private void sleep() throws IOException {
        try {
            Thread.sleep(tick.toMillis());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Streaming export interrupted", e);
        }
    }

    private void requireProject(String projectKey) {
        Integer count = database.jdbc().queryForObject("select count(*) from project where project_key = :key",
                new MapSqlParameterSource("key", projectKey), Integer.class);
        if (count == null || count == 0) {
            throw new BusinessNotFoundException("project", projectKey);
        }
    }

    /** The first N documents of the project in key order; the same request always exports the same documents. */
    private List<ExportedDocument> selectDocuments(String projectKey, int items) {
        return database.jdbc().query("""
                        select document_key, title, revision from document
                         where project_key = :project order by document_key limit :items""",
                new MapSqlParameterSource("project", projectKey).addValue("items", items),
                (rs, n) -> new ExportedDocument(rs.getString(1), rs.getString(2), rs.getString(3)));
    }

    private void insertJob(UUID jobId, BusinessRequest request, String projectKey, String mode, int items) {
        database.jdbc().update("""
                        insert into export_job (job_id, run_id, request_id, control, username, project_key, mode,
                                                requested_items, delivered_items, status, started_at)
                        values (:job, :run, :request, :control, :user, :project, :mode, :items, 0, 'RUNNING', :at)""",
                new MapSqlParameterSource("job", jobId).addValue("run", request.runId())
                        .addValue("request", request.requestId()).addValue("control", request.control())
                        .addValue("user", request.username()).addValue("project", projectKey)
                        .addValue("mode", mode).addValue("items", items)
                        .addValue("at", Timestamp.from(clock.instant())));
    }

    private void finishJob(UUID jobId, int delivered, String status, String manifest) {
        database.jdbc().update("""
                        update export_job set delivered_items = :delivered, status = :status,
                                              manifest_sha256 = :manifest, finished_at = :at
                         where job_id = :job""",
                new MapSqlParameterSource("job", jobId).addValue("delivered", delivered).addValue("status", status)
                        .addValue("manifest", manifest).addValue("at", Timestamp.from(clock.instant())));
    }

    static String manifest(List<String> documentKeys) {
        MessageDigest digest = sha256();
        documentKeys.forEach(key -> digest.update((key + "\n").getBytes(StandardCharsets.UTF_8)));
        return HexFormat.of().formatHex(digest.digest());
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }
}
