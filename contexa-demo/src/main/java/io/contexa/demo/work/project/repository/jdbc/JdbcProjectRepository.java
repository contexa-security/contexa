package io.contexa.demo.work.project.repository.jdbc;

import io.contexa.demo.shared.persistence.AbstractJdbcRepository;
import io.contexa.demo.work.project.dto.ProjectView;
import io.contexa.demo.work.project.repository.ProjectRepository;
import io.contexa.demo.work.shared.dto.WorkText;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
@Profile({"baseline", "contexa"})
public class JdbcProjectRepository extends AbstractJdbcRepository implements ProjectRepository {

    public JdbcProjectRepository(@Qualifier("jdbcTemplate") JdbcOperations jdbc) {
        super(jdbc);
    }

    public List<ProjectView> list(String username) {
        return jdbc.query("""
                select p.*, exists(select 1 from lab.project_assignment a
                    where a.project_id=p.id and a.username=?) as assigned,
                    (select count(distinct d.id) from lab.business_document d where d.project_id=p.id) as document_count
                from lab.business_project p order by assigned desc, p.code
                """, (rs, row) -> new ProjectView(rs.getString("id"), rs.getString("code"),
                new WorkText(rs.getString("title_ko"), rs.getString("title_en")),
                new WorkText(rs.getString("summary_ko"), rs.getString("summary_en")),
                rs.getString("department"), rs.getBoolean("assigned"), rs.getInt("document_count")), username);
    }

    public List<String> assignedProjects(String username) {
        return jdbc.queryForList("""
                select project_id from lab.project_assignment where username=? order by project_id
                """, String.class, username);
    }
}
