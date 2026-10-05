package io.contexa.showcase.portal.combination;

import io.contexa.showcase.business.company.TimeSlot;
import io.contexa.showcase.business.work.BusinessOperation;
import io.contexa.showcase.portal.scenario.ScenarioDefinition;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * The 192 cells of the exploration grid as scenarios (docs/showcase/P4-설계.md 1절). Every cell exports GB-500 design
 * documents (Q-25); a ticket, when present, is named in the request. Cells are explored, not scored, so their ground
 * truth is UNCERTAIN and the visitor answers any additional check.
 */
public final class CombinationCatalog {

    /** Changes whenever a cell's scenario changes; records of another catalog version are not reused. */
    public static final int VERSION = 1;
    static final String PROJECT = "GB-500";
    static final String MISMATCHED_PROJECT = "CP-330";
    static final String TICKET_APPROVER = "pm-11";

    private CombinationCatalog() {
    }

    public static List<Combination> all() {
        List<Combination> all = new ArrayList<>();
        for (String employee : Combination.EMPLOYEES) {
            for (TimeSlot slot : TimeSlot.values()) {
                for (int items : Combination.ITEMS) {
                    for (Combination.Ticket ticket : Combination.Ticket.values()) {
                        for (Combination.Device device : Combination.Device.values()) {
                            all.add(new Combination(employee, slot, items, ticket, device));
                        }
                    }
                }
            }
        }
        return all;
    }

    public static ScenarioDefinition scenario(Combination combination) {
        List<ScenarioDefinition.Fact> facts = new ArrayList<>();
        String claimed = null;
        if (combination.ticket() != Combination.Ticket.NONE) {
            String project = combination.ticket() == Combination.Ticket.MATCH ? PROJECT : MISMATCHED_PROJECT;
            facts.add(new ScenarioDefinition.Fact("TICKET", "INCIDENT", TICKET_APPROVER, project, "INCIDENT_RECOVERY",
                    null, Duration.ofHours(-1), Duration.ofHours(5), "OPEN", null, null, null, null));
            claimed = "{fact:1}";
        }
        ScenarioDefinition.Step step = new ScenarioDefinition.Step(BusinessOperation.EXPORT, null, PROJECT, null,
                combination.items(), 0, Map.of(), claimed, null, null);
        return new ScenarioDefinition(combination.key(), VERSION,
                Map.of("ko", "조건 탐색 " + combination.key(), "en", "Exploration " + combination.key()),
                combination.employee(), true, combination.slot(),
                combination.device() == Combination.Device.NEW ? ScenarioDefinition.Device.NEW
                        : ScenarioDefinition.Device.USUAL,
                ScenarioDefinition.Pace.PACED, facts, List.of(step),
                new ScenarioDefinition.Oracle("UNCERTAIN", List.of("ALLOW", "CHALLENGE", "ESCALATE", "BLOCK")),
                ScenarioDefinition.Network.OFFICE);
    }
}
