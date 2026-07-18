package io.contexa.contexaiam.admin.promptquality.official.application;

import java.util.List;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CustomerDisplayPayloadFactoryTest {

    private final CustomerDisplayPayloadFactory factory = new CustomerDisplayPayloadFactory();

    @Test
    void createsContractRolePayloadsForFailedPurposeResult() {
        CustomerDisplayPayloadFactory.Payload payload = factory.create(new CustomerDisplayPayloadFactory.Request(
                "Authentication risk signal is incomplete.",
                List.of(new CustomerDisplayPayloadFactory.EvidenceDisplay(
                        "Authentication risk signal is incomplete.",
                        "The prompt does not explain why the authentication risk changes the decision.")),
                "The model cannot distinguish a normal user from an attacker without this signal.",
                "Add the missing authentication risk explanation to the user prompt.",
                "The next verification must show the authentication risk explanation.",
                "PURPOSE_FAILED"));

        assertThat(payload.rolePayloads())
                .extracting(CustomerDisplayPayloadFactory.RolePayload::displayRole)
                .containsExactly("TITLE", "FAIL_EVIDENCE", "WHY_IT_MATTERS", "RESOLUTION_ACTION", "REVERIFY_CONDITION");
        assertThat(payload.evidenceText())
                .isEqualTo("The prompt does not explain why the authentication risk changes the decision.");
        assertThat(payload.rolePayloads())
                .anySatisfy(row -> {
                    assertThat(row.displayRole()).isEqualTo("TITLE");
                    assertThat(row.title()).isEqualTo("Authentication risk signal is incomplete.");
                    assertThat(row.summary()).isBlank();
                })
                .anySatisfy(row -> {
                    assertThat(row.displayRole()).isEqualTo("FAIL_EVIDENCE");
                    assertThat(row.title()).isBlank();
                    assertThat(row.summary()).isBlank();
                    assertThat(row.evidenceText())
                            .isEqualTo("The prompt does not explain why the authentication risk changes the decision.");
                });
    }

    @Test
    void createsPassEvidenceRoleForPassedPurposeResult() {
        CustomerDisplayPayloadFactory.Payload payload = factory.create(new CustomerDisplayPayloadFactory.Request(
                "RAG authorization is not applicable.",
                List.of(new CustomerDisplayPayloadFactory.EvidenceDisplay(
                        "RAG authorization is not applicable.",
                        "No retrieved document was used as decision evidence in this request.")),
                "Document authorization is only evaluated when retrieved documents affect the prompt.",
                "",
                "",
                "NOT_APPLICABLE"));

        assertThat(payload.rolePayloads())
                .extracting(CustomerDisplayPayloadFactory.RolePayload::displayRole)
                .containsExactly("TITLE", "PASS_EVIDENCE", "WHY_IT_MATTERS");
        assertThat(payload.rolePayloads())
                .anySatisfy(row -> {
                    assertThat(row.displayRole()).isEqualTo("TITLE");
                    assertThat(row.title()).isEqualTo("RAG authorization is not applicable.");
                    assertThat(row.summary()).isBlank();
                })
                .anySatisfy(row -> {
                    assertThat(row.displayRole()).isEqualTo("PASS_EVIDENCE");
                    assertThat(row.title()).isBlank();
                    assertThat(row.summary()).isBlank();
                    assertThat(row.evidenceText())
                            .isEqualTo("No retrieved document was used as decision evidence in this request.");
                });
    }

    @Test
    void rejectsRawTechnicalEvidenceBeforePersistence() {
        assertThatThrownBy(() -> factory.create(new CustomerDisplayPayloadFactory.Request(
                "Prompt evidence is incomplete.",
                List.of(new CustomerDisplayPayloadFactory.EvidenceDisplay(
                        "Prompt evidence is incomplete.",
                        "DeviceBrowser=Chrome")),
                "The model cannot use raw fields directly.",
                "",
                "",
                "PURPOSE_FAILED")))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Customer display payload contains raw technical evidence");
    }

    @Test
    void rejectsUnresolvedContractPlaceholderBeforePersistence() {
        assertThatThrownBy(() -> factory.create(new CustomerDisplayPayloadFactory.Request(
                "Prompt evidence is incomplete.",
                List.of(new CustomerDisplayPayloadFactory.EvidenceDisplay(
                        "Prompt evidence is incomplete.",
                        "The request actor is {{userSignal}}.")),
                "The model cannot use unresolved template placeholders.",
                "",
                "",
                "PURPOSE_FAILED")))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Customer display payload contains raw technical evidence");
    }

    @Test
    void rejectsMissingEvidence() {
        assertThatThrownBy(() -> factory.create(new CustomerDisplayPayloadFactory.Request(
                "Prompt evidence is incomplete.",
                List.of(),
                "The model needs usable evidence.",
                "",
                "",
                "PURPOSE_FAILED")))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("requires evidence");
    }
}
