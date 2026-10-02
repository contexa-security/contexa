package io.contexa.demo.work.document.repository.jdbc;

import io.contexa.demo.shared.persistence.AbstractJdbcRepository;
import io.contexa.demo.work.document.dto.DocumentBody;
import io.contexa.demo.work.document.dto.DocumentSummary;
import io.contexa.demo.work.document.repository.DocumentRepository;
import io.contexa.demo.work.shared.dto.WorkText;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.stereotype.Repository;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;

@Repository
@Profile({"baseline", "contexa"})
public class JdbcDocumentRepository extends AbstractJdbcRepository implements DocumentRepository {

    public JdbcDocumentRepository(@Qualifier("jdbcTemplate") JdbcOperations jdbc) {
        super(jdbc);
    }

    public List<DocumentSummary> search(String projectId, String search) {
        return jdbc.query("""
                select d.* from lab.business_document d
                where d.project_id=? and (strpos(lower(d.title_ko),lower(?))>0
                    or strpos(lower(d.title_en),lower(?))>0)
                    and d.version=(select max(v.version) from lab.business_document v where v.id=d.id)
                order by d.updated_at desc,d.id limit 100
                """, (rs, row) -> summary(rs), projectId, search, search);
    }

    public DocumentSummary find(String id) {
        return first(jdbc.query("""
                select * from lab.business_document where id=? order by version desc limit 1
                """, (rs, row) -> summary(rs), id));
    }

    public DocumentBody read(String id, int version) {
        return first(jdbc.query("select * from lab.business_document where id=? and version=?",
                (rs, row) -> new DocumentBody(summary(rs),
                        new WorkText(rs.getString("body_ko"), rs.getString("body_en"))), id, version));
    }

    private DocumentSummary summary(ResultSet rs) throws SQLException {
        return new DocumentSummary(rs.getString("id"), rs.getInt("version"), rs.getString("project_id"),
                new WorkText(rs.getString("title_ko"), rs.getString("title_en")),
                new WorkText(rs.getString("summary_ko"), rs.getString("summary_en")),
                rs.getString("sensitivity"), rs.getString("author_name"), rs.getTimestamp("updated_at").toInstant());
    }
}
