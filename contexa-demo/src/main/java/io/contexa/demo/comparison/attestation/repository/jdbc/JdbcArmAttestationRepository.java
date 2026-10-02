package io.contexa.demo.comparison.attestation.repository.jdbc;

import io.contexa.demo.comparison.attestation.dto.ArmAttestation;
import io.contexa.demo.comparison.attestation.repository.ArmAttestationRepository;
import io.contexa.demo.shared.document.DocumentCodec;
import io.contexa.demo.shared.persistence.AbstractJsonJdbcRepository;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.stereotype.Repository;
import org.springframework.web.server.ResponseStatusException;
import java.sql.Timestamp;
import java.util.UUID;

@Repository
@Profile({"baseline", "contexa"})
public class JdbcArmAttestationRepository extends AbstractJsonJdbcRepository implements ArmAttestationRepository {

    public JdbcArmAttestationRepository(@Qualifier("jdbcTemplate") JdbcOperations jdbc, DocumentCodec documents) {
        super(jdbc, documents);
    }

    @Override
    public ArmAttestation findCommand(UUID visitorId, UUID commandId) {
        return first(jdbc.query("""
                select attestation::text from lab.comparison_arm_attestation where visitor_id=? and command_id=?
                """, (rs, row) -> documents.read(rs.getString(1), ArmAttestation.class), visitorId, commandId));
    }

    @Override
    public ArmAttestation save(ArmAttestation candidate) {
        jdbc.update("""
                insert into lab.comparison_arm_attestation
                    (id,visitor_id,workspace_id,preparation_id,command_id,arm,captured_at,snapshot_sha256,attestation)
                values (?,?,?,?,?,?,?,?,cast(? as jsonb)) on conflict(visitor_id,command_id) do nothing
                """, candidate.id(), candidate.visitorId(), candidate.workspaceId(), candidate.preparationId(),
                candidate.commandId(), candidate.arm(), Timestamp.from(candidate.capturedAt()),
                candidate.snapshotSha256(), documents.write(candidate));
        ArmAttestation stored = findCommand(candidate.visitorId(), candidate.commandId());
        if (stored == null || !stored.preparationId().equals(candidate.preparationId())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "COMMAND_INPUT_CHANGED");
        }
        return stored;
    }
}
