package io.contexa.demo.work.customer.repository.jdbc;

import io.contexa.demo.shared.persistence.AbstractJdbcRepository;
import io.contexa.demo.work.customer.dto.CustomerActivity;
import io.contexa.demo.work.customer.dto.CustomerDetail;
import io.contexa.demo.work.customer.dto.CustomerSummary;
import io.contexa.demo.work.customer.repository.CustomerRepository;
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
public class JdbcCustomerRepository extends AbstractJdbcRepository implements CustomerRepository {

    public JdbcCustomerRepository(@Qualifier("jdbcTemplate") JdbcOperations jdbc) {
        super(jdbc);
    }

    @Override
    public List<CustomerSummary> search(String projectId, String search) {
        return jdbc.query("""
                select c.* from lab.business_customer c
                where (?='' or c.project_id=?) and (strpos(lower(c.name_ko),lower(?))>0
                    or strpos(lower(c.name_en),lower(?))>0 or strpos(lower(c.id),lower(?))>0)
                    and c.version=(select max(v.version) from lab.business_customer v where v.id=c.id)
                order by c.project_id,c.id limit 100
                """, (rs, row) -> summary(rs), projectId, projectId, search, search, search);
    }

    @Override
    public CustomerSummary find(String id) {
        return first(jdbc.query("select * from lab.business_customer where id=? order by version desc limit 1",
                (rs, row) -> summary(rs), id));
    }

    @Override
    public CustomerDetail read(String id, int version) {
        List<CustomerActivity> activities = jdbc.query("""
                select * from lab.customer_activity where customer_id=? and customer_version=?
                order by occurred_at desc,id
                """, (rs, row) -> new CustomerActivity(rs.getTimestamp("occurred_at").toInstant(),
                new WorkText(rs.getString("title_ko"), rs.getString("title_en")),
                new WorkText(rs.getString("note_ko"), rs.getString("note_en"))), id, version);
        return first(jdbc.query("select * from lab.business_customer where id=? and version=?",
                (rs, row) -> new CustomerDetail(summary(rs), rs.getString("contact_name"),
                        rs.getString("contact_email"),
                        new WorkText(rs.getString("service_plan_ko"), rs.getString("service_plan_en")), activities),
                id, version));
    }

    private CustomerSummary summary(ResultSet rs) throws SQLException {
        return new CustomerSummary(rs.getString("id"), rs.getInt("version"), rs.getString("project_id"),
                new WorkText(rs.getString("name_ko"), rs.getString("name_en")),
                new WorkText(rs.getString("industry_ko"), rs.getString("industry_en")),
                new WorkText(rs.getString("region_ko"), rs.getString("region_en")),
                rs.getString("sensitivity"), rs.getTimestamp("updated_at").toInstant());
    }
}
