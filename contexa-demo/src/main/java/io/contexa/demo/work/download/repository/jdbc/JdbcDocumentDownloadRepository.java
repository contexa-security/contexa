package io.contexa.demo.work.download.repository.jdbc;

import io.contexa.demo.shared.document.DocumentCodec;
import io.contexa.demo.shared.persistence.AbstractJdbcRepository;
import io.contexa.demo.work.download.dto.DocumentDownloadInput;
import io.contexa.demo.work.download.dto.DocumentDownloadResult;
import io.contexa.demo.work.shared.dto.BusinessFile;
import io.contexa.demo.work.download.repository.DocumentDownloadRepository;
import io.contexa.demo.work.request.dto.BusinessRequestSnapshot;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.support.TransactionOperations;
import org.springframework.web.server.ResponseStatusException;

import java.nio.charset.StandardCharsets;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

@Repository
@Profile({"baseline", "contexa"})
public class JdbcDocumentDownloadRepository extends AbstractJdbcRepository implements DocumentDownloadRepository {

    private final TransactionOperations transactions;
    private final DocumentCodec documents;

    public JdbcDocumentDownloadRepository(@Qualifier("jdbcTemplate") JdbcOperations jdbc,
            @Qualifier("applicationTransactions") TransactionOperations transactions, DocumentCodec documents) {
        super(jdbc);
        this.transactions = transactions;
        this.documents = documents;
    }

    @Override
    public DocumentDownloadResult saveOrReuse(BusinessRequestSnapshot snapshot, DocumentDownloadInput input,
            String content) {
        return transactions.execute(status -> store(snapshot, input, content));
    }

    private DocumentDownloadResult store(BusinessRequestSnapshot snapshot, DocumentDownloadInput input,
            String content) {
        var participant = snapshot.participant();
        List<Object> fingerprintValues = new ArrayList<>(List.of(participant.workspaceId(), participant.username(),
                snapshot.document().id(), snapshot.document().version(), input.purpose(), input.language()));
        if (input.approvalId() != null) {
            fingerprintValues.add(input.approvalId());
        }
        String fingerprint = documents.hash(documents.write(fingerprintValues));
        String filename = snapshot.document().id().replaceAll("[^a-zA-Z0-9-]", "_")
                + "-v" + snapshot.document().version() + "-" + input.language().name().toLowerCase(Locale.ROOT) + ".txt";
        int inserted = jdbc.update("""
                insert into lab.document_file
                    (id, visitor_id, command_id, workspace_id, username, document_id, document_version,
                     language, purpose, input_sha256, filename, content, content_sha256, prepared_at)
                values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                on conflict (visitor_id, command_id) do nothing
                """, UUID.randomUUID(), participant.visitorId(), input.commandId(), participant.workspaceId(),
                participant.username(), snapshot.document().id(), snapshot.document().version(), input.language().name(),
                input.purpose().name(), fingerprint, filename, content.getBytes(StandardCharsets.UTF_8),
                documents.hash(content), Timestamp.from(Instant.now()));
        BusinessFile file = first(jdbc.query("""
                select id, input_sha256, filename, content_sha256, content, prepared_at
                from lab.document_file where visitor_id=? and command_id=?
                """, (rs, row) -> new BusinessFile(rs.getObject("id", UUID.class), rs.getString("input_sha256"),
                rs.getString("filename"), rs.getString("content_sha256"), rs.getBytes("content"),
                rs.getTimestamp("prepared_at").toInstant()), participant.visitorId(), input.commandId()));
        if (file == null) {
            throw new IllegalStateException("Prepared document file is unavailable");
        }
        if (!fingerprint.equals(file.inputSha256())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "COMMAND_INPUT_CHANGED");
        }
        jdbc.update("""
                insert into lab.document_download_attempt (request_id, file_id, reused, prepared_at)
                values (?, ?, ?, ?)
                """, snapshot.requestId(), file.id(), inserted == 0, Timestamp.from(Instant.now()));
        return new DocumentDownloadResult(file, inserted == 0);
    }
}
