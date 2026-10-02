package io.contexa.demo.work.customer.repository.jdbc;

import io.contexa.demo.shared.persistence.AbstractJdbcRepository;
import io.contexa.demo.work.customer.dto.CustomerReadResult;
import io.contexa.demo.work.customer.repository.CustomerReadRepository;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;

@Repository
@Profile({"baseline", "contexa"})
public class JdbcCustomerReadRepository extends AbstractJdbcRepository implements CustomerReadRepository {

    public JdbcCustomerReadRepository(@Qualifier("jdbcTemplate") JdbcOperations jdbc) {
        super(jdbc);
    }

    @Override
    public void append(CustomerReadResult result) {
        jdbc.update("""
                insert into lab.business_customer_read
                    (request_id,customer_id,customer_version,content_sha256,content_bytes,completed_at)
                values (?,?,?,?,?,?)
                """, result.requestId(), result.detail().customer().id(), result.detail().customer().version(),
                result.contentSha256(), result.contentBytes(), Timestamp.from(result.completedAt()));
    }
}
