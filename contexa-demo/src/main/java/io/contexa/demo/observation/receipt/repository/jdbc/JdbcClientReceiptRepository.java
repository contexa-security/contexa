package io.contexa.demo.observation.receipt.repository.jdbc;

import io.contexa.demo.observation.receipt.dto.ClientReceiptView;
import io.contexa.demo.observation.receipt.repository.ClientReceiptRepository;
import io.contexa.demo.shared.document.DocumentCodec;
import io.contexa.demo.shared.persistence.AbstractJsonJdbcRepository;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.stereotype.Repository;
import org.springframework.web.server.ResponseStatusException;

import java.sql.Timestamp;
import java.util.List;
import java.util.UUID;

@Repository
@Profile("portal")
public class JdbcClientReceiptRepository extends AbstractJsonJdbcRepository implements ClientReceiptRepository {

    public JdbcClientReceiptRepository(@Qualifier("jdbcTemplate") JdbcOperations jdbc, DocumentCodec documents) {
        super(jdbc, documents);
    }

    @Override
    public ClientReceiptView append(UUID visitorId, String inputSha256, ClientReceiptView receipt) {
        jdbc.update("""
                insert into lab.client_receipt
                    (id, visitor_id, arm, request_id, input_sha256, reported_at, receipt)
                values (?, ?, ?, ?, ?, ?, cast(? as jsonb)) on conflict do nothing
                """, receipt.id(), visitorId, receipt.arm(), receipt.requestId(), inputSha256,
                Timestamp.from(receipt.reportedAt()), documents.write(receipt));
        ClientReceiptView stored = first(jdbc.query("""
                select receipt::text from lab.client_receipt
                where id=? and visitor_id=? and arm=? and request_id=? and input_sha256=?
                """, (rs, row) -> documents.read(rs.getString(1), ClientReceiptView.class), receipt.id(), visitorId,
                receipt.arm(), receipt.requestId(), inputSha256));
        if (stored == null) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "RECEIPT_INPUT_CHANGED");
        }
        return stored;
    }

    @Override
    public List<ClientReceiptView> find(String arm, UUID requestId, UUID visitorId) {
        return jdbc.query("""
                select receipt::text from lab.client_receipt
                where arm=? and request_id=? and visitor_id=? order by reported_at, id
                """, (rs, row) -> documents.read(rs.getString(1), ClientReceiptView.class), arm, requestId, visitorId);
    }
}
