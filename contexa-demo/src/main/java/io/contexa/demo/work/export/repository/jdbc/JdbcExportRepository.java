package io.contexa.demo.work.export.repository.jdbc;

import io.contexa.demo.shared.document.DocumentCodec;
import io.contexa.demo.shared.persistence.AbstractJdbcRepository;
import io.contexa.demo.work.export.dto.ExportContent;
import io.contexa.demo.work.export.dto.ExportDownloadResult;
import io.contexa.demo.work.export.dto.ExportInput;
import io.contexa.demo.work.export.dto.ExportItem;
import io.contexa.demo.work.export.dto.ExportRequestSnapshot;
import io.contexa.demo.work.export.repository.ExportRepository;
import io.contexa.demo.work.shared.dto.BusinessFile;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.support.TransactionOperations;
import org.springframework.web.server.ResponseStatusException;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.function.Supplier;

@Repository
@Profile({"baseline", "contexa"})
public class JdbcExportRepository extends AbstractJdbcRepository implements ExportRepository {

    private final TransactionOperations transactions;
    private final DocumentCodec documents;

    public JdbcExportRepository(@Qualifier("jdbcTemplate") JdbcOperations jdbc,
            @Qualifier("applicationTransactions") TransactionOperations transactions, DocumentCodec documents) {
        super(jdbc);
        this.transactions = transactions;
        this.documents = documents;
    }

    @Override
    public ExportDownloadResult saveOrReuse(ExportRequestSnapshot snapshot, ExportInput input,
            Supplier<ExportContent> content) {
        return transactions.execute(status -> store(snapshot, input, content));
    }

    private ExportDownloadResult store(ExportRequestSnapshot snapshot, ExportInput input,
            Supplier<ExportContent> contentSource) {
        var participant = snapshot.participant();
        List<Object> values = new ArrayList<>(List.of(participant.workspaceId(), participant.username(),
                input.resourceType(), snapshot.targets(), input.purpose(), input.language()));
        if (input.approvalId() != null) {
            values.add(input.approvalId());
        }
        String fingerprint = documents.hash(documents.write(values));
        ExportDownloadResult existing = find(participant.visitorId(), input.commandId(), true);
        if (existing != null) {
            return attempt(snapshot, input, fingerprint, existing);
        }
        ExportContent content = contentSource.get();
        UUID fileId = UUID.randomUUID();
        byte[] bytes = content.bytes();
        Instant now = Instant.now();
        String filename = "export-" + fileId + "." + content.extension();
        int inserted = jdbc.update("""
                insert into lab.export_file
                    (id,visitor_id,workspace_id,username,command_id,resource_type,language,purpose,input_sha256,
                     filename,content_type,content,content_sha256,prepared_items,prepared_at)
                values (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                on conflict (visitor_id,command_id) do nothing
                """, fileId, participant.visitorId(), participant.workspaceId(), participant.username(), input.commandId(),
                input.resourceType().name(), input.language().name(), input.purpose().name(), fingerprint, filename,
                content.contentType(), bytes, documents.hash(bytes), content.items().size(), Timestamp.from(now));
        if (inserted == 1) {
            for (ExportItem item : content.items()) {
                jdbc.update("""
                        insert into lab.export_item (file_id,resource_id,resource_version,content_sha256,content_bytes)
                        values (?,?,?,?,?)
                        """, fileId, item.resourceId(), item.version(), item.contentSha256(), item.contentBytes());
            }
        }
        ExportDownloadResult result = find(participant.visitorId(), input.commandId(), inserted == 0);
        if (result == null) {
            throw new IllegalStateException("Prepared export is unavailable");
        }
        return attempt(snapshot, input, fingerprint, result);
    }

    private ExportDownloadResult attempt(ExportRequestSnapshot snapshot, ExportInput input, String fingerprint,
            ExportDownloadResult result) {
        if (!result.file().inputSha256().equals(fingerprint)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "COMMAND_INPUT_CHANGED");
        }
        jdbc.update("""
                insert into lab.export_attempt (request_id,file_id,command_id,reused,prepared_at)
                values (?,?,?,?,?)
                """, snapshot.requestId(), result.file().id(), input.commandId(), result.reused(), Timestamp.from(Instant.now()));
        return result;
    }

    private ExportDownloadResult find(UUID visitorId, UUID commandId, boolean reused) {
        return first(jdbc.query("""
                select id,input_sha256,filename,content_sha256,content,prepared_at,content_type,prepared_items
                from lab.export_file where visitor_id=? and command_id=?
                """, (rs, row) -> new ExportDownloadResult(new BusinessFile(rs.getObject("id", UUID.class),
                rs.getString("input_sha256"), rs.getString("filename"), rs.getString("content_sha256"), rs.getBytes("content"),
                rs.getTimestamp("prepared_at").toInstant()), rs.getString("content_type"), rs.getInt("prepared_items"), reused),
                visitorId, commandId));
    }
}
