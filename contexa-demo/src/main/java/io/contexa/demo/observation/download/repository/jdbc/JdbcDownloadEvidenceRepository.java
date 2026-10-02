package io.contexa.demo.observation.download.repository.jdbc;

import io.contexa.demo.observation.download.dto.DownloadEvidence;
import io.contexa.demo.observation.download.repository.DownloadEvidenceRepository;
import io.contexa.demo.shared.persistence.AbstractJdbcRepository;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
@Profile({"baseline", "contexa"})
public class JdbcDownloadEvidenceRepository extends AbstractJdbcRepository implements DownloadEvidenceRepository {

    public JdbcDownloadEvidenceRepository(@Qualifier("jdbcTemplate") JdbcOperations jdbc) {
        super(jdbc);
    }

    @Override
    public Optional<DownloadEvidence> find(UUID requestId) {
        return Optional.ofNullable(first(jdbc.query("""
                select f.id, f.filename, f.content_sha256, octet_length(f.content) as prepared_bytes,
                    f.language, f.prepared_at, a.reused, 1 as prepared_items
                from lab.document_download_attempt a join lab.document_file f on f.id=a.file_id
                where a.request_id=?
                union all
                select f.id, f.filename, f.content_sha256, octet_length(f.content) as prepared_bytes,
                    f.language, f.prepared_at, a.reused, f.prepared_items
                from lab.export_attempt a join lab.export_file f on f.id=a.file_id
                where a.request_id=?
                """, (rs, row) -> new DownloadEvidence(rs.getObject("id", UUID.class), rs.getString("filename"),
                rs.getString("content_sha256"), rs.getInt("prepared_bytes"), rs.getString("language"),
                rs.getTimestamp("prepared_at").toInstant(), rs.getBoolean("reused"), rs.getInt("prepared_items")), requestId, requestId)));
    }
}
