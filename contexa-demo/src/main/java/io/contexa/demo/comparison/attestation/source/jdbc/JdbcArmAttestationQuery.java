package io.contexa.demo.comparison.attestation.source.jdbc;

import io.contexa.demo.comparison.attestation.dto.ArmAttestation;
import io.contexa.demo.comparison.attestation.source.ArmAttestationQuery;
import io.contexa.demo.shared.document.DocumentCodec;
import io.contexa.demo.shared.persistence.AbstractJsonJdbcRepository;
import org.springframework.jdbc.core.JdbcOperations;
import java.util.UUID;

public class JdbcArmAttestationQuery extends AbstractJsonJdbcRepository implements ArmAttestationQuery {

    private final String arm;

    public JdbcArmAttestationQuery(String arm, JdbcOperations jdbc, DocumentCodec documents) {
        super(jdbc, documents);
        this.arm = arm;
    }

    @Override
    public String arm() {
        return arm;
    }

    @Override
    public ArmAttestation find(UUID visitorId, UUID preparationId, UUID id) {
        return first(jdbc.query("""
                select attestation::text from lab.comparison_arm_attestation
                where visitor_id=? and preparation_id=? and id=? and arm=?
                """, (rs, row) -> documents.read(rs.getString(1), ArmAttestation.class),
                visitorId, preparationId, id, arm));
    }
}
