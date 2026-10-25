package io.contexa.showcase.portal.orchestrator;

import io.contexa.showcase.business.work.BusinessOperation;
import io.contexa.showcase.portal.agent.AgentWork.Request;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/** docs/agent A7-2b: what a business agent names reaches the company as it named it, encoded into the request. */
class AgentTaskPathsTest {

    private static Request request(BusinessOperation operation, String project, String document, String customer,
                                   Integer items, String type, String query, String grantee, String responsibility) {
        return new Request(operation, project, document, customer, items, type, query, grantee, responsibility);
    }

    @Test
    void eachToolCallIsTheCompanysRequestOfItsOperation() {
        assertThat(RunOrchestrator.agentPath(request(BusinessOperation.PROJECT_LIST, null, null, null, null, null,
                null, null, null))).isEqualTo("/api/projects");
        assertThat(RunOrchestrator.agentPath(request(BusinessOperation.DOCUMENT_LIST, "HX-310", null, null, null,
                "DRAWING", "rotor shaft", null, null))).isEqualTo("/api/projects/HX-310/documents?type=DRAWING&q=rotor+shaft");
        assertThat(RunOrchestrator.agentPath(request(BusinessOperation.DOCUMENT_LIST, "HX-310", null, null, null,
                null, " ", null, null))).isEqualTo("/api/projects/HX-310/documents");
        assertThat(RunOrchestrator.agentPath(request(BusinessOperation.DOCUMENT_READ, null, "DOC-7", null, null,
                null, null, null, null))).isEqualTo("/api/documents/DOC-7");
        assertThat(RunOrchestrator.agentPath(request(BusinessOperation.DOCUMENT_DOWNLOAD, null, "DOC-7", null, null,
                null, null, null, null))).isEqualTo("/api/documents/DOC-7/download");
        assertThat(RunOrchestrator.agentPath(request(BusinessOperation.EXPORT, "GB-500", null, null, 40, null, null,
                null, null))).isEqualTo("/api/projects/GB-500/exports?items=40");
        assertThat(RunOrchestrator.agentPath(new Request(BusinessOperation.EXPORT, "HX-310", null, null, 40, null, null,
                null, null, "TCK 9"))).as("the ticket an export claims goes in its query, encoded")
                .isEqualTo("/api/projects/HX-310/exports?items=40&claimedTicket=TCK+9");
        assertThat(RunOrchestrator.agentPath(new Request(BusinessOperation.EXPORT, "HX-310", null, null, 40, null,
                null, null, null, null, "drop.example.net/in"))).as("where an export goes is in its query, encoded")
                .isEqualTo("/api/projects/HX-310/exports?items=40&destination=drop.example.net%2Fin");
        assertThat(RunOrchestrator.agentPath(new Request(BusinessOperation.EXPORT, "HX-310", null, null, 40, null,
                null, null, null, "TCK-1", "design-share"))).isEqualTo(
                "/api/projects/HX-310/exports?items=40&claimedTicket=TCK-1&destination=design-share");
        assertThat(RunOrchestrator.agentPath(request(BusinessOperation.DOCUMENT_DELETE, null, "DOC-7", null, null,
                null, null, null, null))).as("a deletion is a POST of its own").isEqualTo("/api/documents/DOC-7/delete");
        assertThat(ControlSession.method(BusinessOperation.DOCUMENT_DELETE)).isEqualTo("POST");
        assertThat(EngineDecision.synchronous(BusinessOperation.DOCUMENT_DELETE)).isTrue();
        assertThat(RunOrchestrator.agentPath(request(BusinessOperation.CUSTOMER_READ, null, null, "CUS-0001", null,
                null, null, null, null))).isEqualTo("/api/customers/CUS-0001");
        assertThat(RunOrchestrator.agentPath(request(BusinessOperation.ROLE_GRANT, "HX-310", null, null, null, null,
                null, "E-0042", "REVIEW"))).isEqualTo("/api/admin/role-grants?project=HX-310&grantee=E-0042"
                + "&responsibility=REVIEW");
    }

    /** docs/agent A6-C14: the person names the run's own ticket to the agent; its key is made per run. */
    @Test
    void anInstructionNamesTheRunsOwnFactsByTheirPlaceInTheCase() {
        assertThat(RunOrchestrator.withFactKeys("Export for incident {{TCK:1}} (approval {{APR:2}}).", "9e971454c4de"))
                .isEqualTo("Export for incident TCK-9e971454c4de-1 (approval APR-9e971454c4de-2).");
        assertThat(RunOrchestrator.withFactKeys("No fact is named, {{ticket}} stays.", "9e971454c4de"))
                .isEqualTo("No fact is named, {{ticket}} stays.");
        assertThat(RunOrchestrator.factKey("DLG", "9e971454c4de", 3)).isEqualTo("DLG-9e971454c4de-3");
    }

    @Test
    void whatTheAgentNamesCannotLeaveItsPathSegment() {
        assertThat(RunOrchestrator.agentPath(request(BusinessOperation.DOCUMENT_READ, null, "../admin/x?y=1", null,
                null, null, null, null, null))).isEqualTo("/api/documents/..%2Fadmin%2Fx%3Fy%3D1");
        assertThat(RunOrchestrator.agentPath(request(BusinessOperation.EXPORT, "HX 310", null, null, null, null, null,
                null, null))).as("an export without a count is sent as the agent asked it")
                .isEqualTo("/api/projects/HX%20310/exports?items=");
        assertThat(RunOrchestrator.agentPath(request(BusinessOperation.ROLE_GRANT, "HX-310", null, null, null, null,
                null, "E-1&responsibility=OWNER", "REVIEW"))).isEqualTo("/api/admin/role-grants?project=HX-310"
                + "&grantee=E-1%26responsibility%3DOWNER&responsibility=REVIEW");
    }
}
