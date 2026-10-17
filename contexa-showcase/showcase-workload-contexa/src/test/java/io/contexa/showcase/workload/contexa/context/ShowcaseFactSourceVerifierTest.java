package io.contexa.showcase.workload.contexa.context;

import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.prompt.PromptBlock;
import io.contexa.contexacore.verification.inspection.InspectedPrompt;
import io.contexa.contexacore.verification.inspection.PromptFactSourceVerifier.SourceFact;
import io.contexa.contexacore.verification.inspection.PromptFactSourceVerifier.SourceReading;
import io.contexa.contexacore.verification.inspection.PromptInspectionSubject;
import io.contexa.contexacore.verification.inspection.PromptInspectionUnavailableException;
import io.contexa.showcase.business.work.WorkDatabase;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.jdbc.core.namedparam.SqlParameterSource;

import java.sql.ResultSet;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * W6-7 (P6-CHANGE-5): the showcase reads its own company records of a sealed request again and gives the pieces the
 * dictionary lines must hold.
 */
class ShowcaseFactSourceVerifierTest {

    private static final String PROMPT = """
            === DECISION FACTS ===
            [F5] Approval: APR-1 by pm-11, APPROVED, up to 5,000 items, used 480 before this request
            """;

    private final NamedParameterJdbcTemplate jdbc = mock(NamedParameterJdbcTemplate.class);
    private final WorkDatabase database = mock(WorkDatabase.class);

    @Test
    void theOnCallTheAssignmentAndTheNamedApprovalAreReadFromTheWorkDatabase() throws Exception {
        when(database.jdbc()).thenReturn(jdbc);
        rows("from run_principal", "EMP-1", "run-1");
        when(jdbc.queryForObject(contains("from oncall_roster"), any(SqlParameterSource.class), eq(Integer.class)))
                .thenReturn(0);
        when(jdbc.queryForObject(contains("from project_assignment"), any(SqlParameterSource.class), eq(Integer.class)))
                .thenReturn(1);
        approvalRow("pm-11", 5000, 480);

        List<SourceFact> facts = new ShowcaseFactSourceVerifier(database, "D").sourceFacts(subject());

        assertThat(facts).containsExactly(
                new SourceFact(PromptBlock.DECISION_FACTS, "OnCall", "not on call", null,
                        "showcase work database oncall_roster"),
                new SourceFact(PromptBlock.DECISION_FACTS, "Assignment", "assigned to GB-500", "not assigned to GB-500",
                        "showcase work database project_assignment"),
                new SourceFact(PromptBlock.DECISION_FACTS, "Approval", "APR-1 by pm-11", null,
                        "showcase work database approval"),
                new SourceFact(PromptBlock.DECISION_FACTS, "Approval", "up to 5,000 items", null,
                        "showcase work database approval"),
                new SourceFact(PromptBlock.DECISION_FACTS, "Approval", "used 480 before this request", null,
                        "showcase work database export_job"));
    }

    @Test
    void aWorkDatabaseThatCannotBeReadInspectsThePackageAgainLater() {
        when(database.jdbc()).thenReturn(jdbc);
        when(jdbc.query(contains("from run_principal"), any(SqlParameterSource.class), any(RowMapper.class)))
                .thenThrow(new DataAccessResourceFailureException("down"));

        assertThatThrownBy(() -> new ShowcaseFactSourceVerifier(database, "D").sourceFacts(subject()))
                .isInstanceOf(PromptInspectionUnavailableException.class);
    }

    /**
     * N-SRC-2: a request user the work database no longer holds (the run rows go when the run ends) is a record not
     * kept, where the verifier looked; not a source without facts, and not a database to read again later.
     */
    @Test
    @SuppressWarnings("unchecked")
    void aUserTheWorkDatabaseNoLongerHoldsIsARecordNotKept() {
        when(database.jdbc()).thenReturn(jdbc);
        when(jdbc.query(contains("from run_principal"), any(SqlParameterSource.class), any(RowMapper.class)))
                .thenReturn(List.of());
        ShowcaseFactSourceVerifier verifier = new ShowcaseFactSourceVerifier(database, "D");

        SourceReading reading = verifier.read(subject());

        assertThat(reading.recordsKept()).isFalse();
        assertThat(reading.notKeptRef()).isEqualTo("showcase work database run_principal");
        assertThat(reading.facts()).isEmpty();
        assertThat(verifier.sourceFacts(subject())).isEmpty();
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private void rows(String table, String first, String second) throws Exception {
        ResultSet rs = mock(ResultSet.class);
        when(rs.getString(1)).thenReturn(first);
        when(rs.getString(2)).thenReturn(second);
        when(jdbc.query(contains(table), any(SqlParameterSource.class), any(RowMapper.class)))
                .thenAnswer(invocation -> List.of(((RowMapper) invocation.getArgument(2)).mapRow(rs, 0)));
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private void approvalRow(String approver, int maxItems, int used) throws Exception {
        ResultSet rs = mock(ResultSet.class);
        when(rs.getString(1)).thenReturn(approver);
        when(rs.getInt(2)).thenReturn(maxItems);
        when(rs.getInt(3)).thenReturn(used);
        when(jdbc.query(contains("from approval a"), any(SqlParameterSource.class), any(RowMapper.class)))
                .thenAnswer(invocation -> List.of(((RowMapper) invocation.getArgument(2)).mapRow(rs, 0)));
    }

    private static PromptInspectionSubject subject() {
        CanonicalSecurityContext context = new CanonicalSecurityContext();
        CanonicalSecurityContext.Actor actor = new CanonicalSecurityContext.Actor();
        actor.setUserId("v107-adm-a");
        context.setActor(actor);
        CanonicalSecurityContext.Resource resource = new CanonicalSecurityContext.Resource();
        resource.setRequestPath("/api/projects/GB-500/exports");
        context.setResource(resource);
        context.setRequestObservedAt(Instant.parse("2026-09-30T14:21:00Z"));
        PromptInspectionSubject subject = mock(PromptInspectionSubject.class);
        when(subject.canonicalContext()).thenReturn(context);
        when(subject.prompt()).thenReturn(InspectedPrompt.parse(PROMPT));
        return subject;
    }
}
