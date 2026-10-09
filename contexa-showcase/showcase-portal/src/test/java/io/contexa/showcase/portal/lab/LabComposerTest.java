package io.contexa.showcase.portal.lab;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.contexa.showcase.business.company.TimeSlot;
import io.contexa.showcase.business.work.BusinessOperation;
import io.contexa.showcase.portal.lab.LabComposer.Claim;
import io.contexa.showcase.portal.lab.LabComposer.Composed;
import io.contexa.showcase.portal.lab.LabComposer.Conditions;
import io.contexa.showcase.portal.lab.LabComposer.Place;
import io.contexa.showcase.portal.lab.LabComposer.Refused;
import io.contexa.showcase.portal.lab.LabComposer.Target;
import io.contexa.showcase.portal.lab.LabComposer.TicketChoice;
import io.contexa.showcase.portal.scenario.ScenarioCatalog;
import io.contexa.showcase.portal.scenario.ScenarioDefinition;
import io.contexa.showcase.portal.scenario.ScenarioDefinition.Fact;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The lab composes only what the visitor changed (docs/showcase/데모-재설계.md 5A.1.1, W2-1). The business data in
 * test/resources/lab/lab-options.json was read from the development business database with the queries of the
 * business application's lab-options endpoint.
 */
class LabComposerTest {

    private static final ObjectMapper JSON = new ObjectMapper().findAndRegisterModules();
    private final ScenarioCatalog catalog;
    private final LabComposer composer;
    private final LabData data;

    LabComposerTest() throws IOException {
        catalog = new ScenarioCatalog(JSON);
        composer = new LabComposer(catalog, JSON);
        try (InputStream in = LabComposerTest.class.getResourceAsStream("/lab/lab-options.json")) {
            data = LabData.of(JSON.readTree(in));
        }
    }

    private static Conditions only() {
        return new Conditions(null, null, null, null, null, null, null, null, null, null, null);
    }

    @Test
    void everyDesignedCaseRunsAsDesignedWhenNothingChanges() {
        for (ScenarioDefinition scenario : catalog.all()) {
            Composed composed = composer.compose(scenario.key(), only(), data);
            assertThat(composed.designed()).as(scenario.key()).isTrue();
            assertThat(composed.definition()).as(scenario.key()).isSameAs(scenario);
            Conditions own = composer.conditions(scenario, data);
            assertThat(composer.compose(scenario.key(), own, data).designed())
                    .as("%s sent back with its own conditions", scenario.key()).isTrue();
        }
    }

    @Test
    void theConditionsOfACaseAreReadFromItsDefinitionAndTheBusinessData() {
        Conditions a3 = composer.conditions(catalog.find("A3").orElseThrow(), data);
        assertThat(a3).isEqualTo(new Conditions("adm-a", TimeSlot.DAWN, Place.OFFICE, ScenarioDefinition.Device.USUAL,
                BusinessOperation.EXPORT, Target.UNASSIGNED, 4831, false, TicketChoice.NONE, Claim.NONE, false));
        Conditions a8t = composer.conditions(catalog.find("A8T").orElseThrow(), data);
        assertThat(a8t.ticket()).isEqualTo(TicketChoice.COVERS);
        assertThat(a8t.claim()).isEqualTo(Claim.REAL);
        assertThat(a8t.onCall()).isTrue();
        assertThat(composer.conditions(catalog.find("A8").orElseThrow(), data).claim()).isEqualTo(Claim.FAKE);
        assertThat(composer.conditions(catalog.find("A1T").orElseThrow(), data).place()).isEqualTo(Place.TRAVEL);
        assertThat(composer.conditions(catalog.find("K2").orElseThrow(), data).target()).isEqualTo(Target.ASSIGNED);
        Conditions a6 = composer.conditions(catalog.find("A6").orElseThrow(), data);
        assertThat(a6.operation()).as("a case of several steps keeps its steps").isNull();
    }

    @Test
    void turningOnAnApprovalAddsARecordShapedLikeA3TsForTheTargetProjectAndItsOwner() {
        Composed composed = composer.compose("A3", new Conditions(null, null, null, null, null, null, null, true,
                null, null, null), data);

        assertThat(composed.designed()).isFalse();
        assertThat(composed.changed()).containsExactly("approval");
        ScenarioDefinition definition = composed.definition();
        assertThat(definition.key()).matches("LAB-[0-9a-f]{12}");
        assertThat(definition.oracle().classification()).isEqualTo(LabComposer.COMPOSED);
        assertThat(definition.steps().get(0).expected()).as("the designed expectations may not hold").isEmpty();
        Fact template = catalog.find("A3T").orElseThrow().facts().get(0);
        assertThat(definition.facts()).singleElement().satisfies(fact -> {
            assertThat(fact.kind()).isEqualTo("APPROVAL");
            assertThat(fact.project()).isEqualTo("GB-500");
            assertThat(fact.approver()).as("GB-500's owner in the business database").isEqualTo("pm-11");
            assertThat(fact.maxItems()).as("covers the request").isEqualTo(4831);
            assertThat(fact.purpose()).isEqualTo(template.purpose());
            assertThat(fact.validFromOffset()).isEqualTo(template.validFromOffset());
            assertThat(fact.status()).isEqualTo(template.status());
        });
        assertThat(composer.compose("A3", new Conditions(null, null, null, null, null, null, null, true, null, null,
                null), data).definition().key()).as("the same composition gets the same key")
                .isEqualTo(definition.key());
    }

    @Test
    void aRealClaimNamesTheRunsTicketAndAFalseClaimIsTheNumberCaseA8Claims() {
        Composed real = composer.compose("A8", new Conditions(null, null, null, null, null, null, null, null,
                TicketChoice.COVERS, Claim.REAL, null), data);
        assertThat(real.definition().facts()).singleElement()
                .satisfies(fact -> assertThat(fact.project()).isEqualTo("GB-500"));
        assertThat(real.definition().steps().get(0).claimedTicket()).isEqualTo("{fact:1}");

        Composed fake = composer.compose("A8T", new Conditions(null, null, null, null, null, null, null, null, null,
                Claim.FAKE, null), data);
        assertThat(fake.definition().steps().get(0).claimedTicket())
                .isEqualTo(catalog.find("A8").orElseThrow().steps().get(0).claimedTicket());

        assertThatThrownBy(() -> composer.compose("A8", new Conditions(null, null, null, null, null, null, null, null,
                null, Claim.REAL, null), data)).isInstanceOf(Refused.class).hasMessage("CLAIM_NEEDS_TICKET");
    }

    @Test
    void theTargetFollowsTheEmployeeAndTheBusinessData() {
        Composed engineer = composer.compose("A3", new Conditions("eng-k", null, null, null, null, null, null, null,
                null, null, null), data);
        assertThat(engineer.definition().protagonist()).isEqualTo("eng-k");
        assertThat(engineer.definition().steps().get(0).project()).as("GB-500 is not eng-k's either")
                .isEqualTo("GB-500");

        Composed admin = composer.compose("K2", new Conditions("adm-a", null, null, null, null, null, null, null,
                null, null, null), data);
        ScenarioDefinition.Step step = admin.definition().steps().get(0);
        assertThat(step.document().project()).as("adm-a's assigned project").isEqualTo("PLM-OPS");
        assertThat(step.document().type()).isEqualTo(data.documentTypes().get("PLM-OPS").get(0));
        assertThat(step.document().position()).isEqualTo(1);
    }

    /**
     * W2-7: for another employee the same kind of request is sent: the designed document type at the designed position
     * in that employee's project, when the project has that type (PLM-OPS above has no drawings).
     */
    @Test
    void anotherEmployeeReadsTheSameKindOfDocumentInTheirOwnProject() throws IOException {
        ObjectNode options;
        try (InputStream in = LabComposerTest.class.getResourceAsStream("/lab/lab-options.json")) {
            options = (ObjectNode) JSON.readTree(in);
        }
        ((ArrayNode) options.get("employees")).addObject().put("employee_key", "eng-01").put("role_key", "ENGINEER")
                .put("display_name", "Design engineer 01").put("department", "Design engineering HX")
                .put("office_network", "10.40.21.0/24");
        ((ArrayNode) options.get("assignments")).addObject().put("project_key", "HX-200").put("employee_key", "eng-01")
                .put("responsibility", "DESIGN");
        LabData withField = LabData.of(options);
        ScenarioDefinition.DocumentSelector designed = catalog.find("K2").orElseThrow().steps().get(0).document();

        Composed field = composer.compose("K2", new Conditions("eng-01", null, null, null, null, null, null, null,
                null, null, null), withField);

        ScenarioDefinition.DocumentSelector document = field.definition().steps().get(0).document();
        assertThat(document.project()).isEqualTo("HX-200");
        assertThat(document.type()).isEqualTo(designed.type());
        assertThat(document.position()).isEqualTo(designed.position());
        assertThat(field.changed()).containsExactly("employee");
    }

    @Test
    void aCaseOfSeveralStepsChangesOnlyItsConditions() {
        Composed later = composer.compose("A6", new Conditions(null, TimeSlot.DAWN, null, null, null, null, null,
                null, null, null, null), data);
        ScenarioDefinition designed = catalog.find("A6").orElseThrow();
        assertThat(later.definition().timeSlot()).isEqualTo(TimeSlot.DAWN);
        assertThat(later.definition().steps()).extracting(ScenarioDefinition.Step::customer)
                .containsExactlyElementsOf(designed.steps().stream().map(ScenarioDefinition.Step::customer).toList());
        assertThat(later.definition().steps()).allSatisfy(step -> assertThat(step.expected()).isEmpty());

        assertThatThrownBy(() -> composer.compose("A6", new Conditions(null, null, null, null,
                BusinessOperation.EXPORT, null, 40, null, null, null, null), data))
                .isInstanceOf(Refused.class).hasMessage("STEPS_FIXED");
    }

    @Test
    void placeAndTravelRecordGoTogether() {
        Composed office = composer.compose("A1T", new Conditions(null, null, Place.OFFICE, null, null, null, null,
                null, null, null, null), data);
        assertThat(office.definition().networkOrDefault()).isEqualTo(ScenarioDefinition.Network.OFFICE);
        assertThat(office.definition().facts()).isEmpty();

        Composed travel = composer.compose("A1", new Conditions(null, null, Place.TRAVEL, null, null, null, null,
                null, null, null, null), data);
        assertThat(travel.definition().facts()).singleElement()
                .isEqualTo(catalog.find("A1T").orElseThrow().facts().get(0));
        assertThat(travel.definition().networkOrDefault()).isEqualTo(ScenarioDefinition.Network.TRAVEL);
        assertThat(List.of(travel.changed())).isNotEmpty();
    }

    @Test
    void anAssignedCustomerIsNotOfferedBecauseTheDataHasNone() {
        assertThatThrownBy(() -> composer.compose("A6", new Conditions(null, null, null, null, null,
                Target.ASSIGNED, null, null, null, null, null), data)).isInstanceOf(Refused.class);
        Composed single = composer.compose("R1", new Conditions(null, TimeSlot.MORNING, null, null, null, null, null,
                null, null, null, null), data);
        assertThat(single.designed()).isFalse();
    }
}
