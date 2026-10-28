package io.contexa.showcase.portal.menu;

import io.contexa.showcase.portal.scenario.DelegationChoice;

import java.util.ArrayList;
import java.util.List;

/**
 * docs/agent Agent중심-화면 AC-4: the agent menu's finite table. AC-4a: five cases, each on the three paths an agent sends its
 * requests on, so fifteen combinations. The cases are the measured ones a visitor can follow in a few requests: a pair
 * on the same export (the work's 40 documents and ten times as many), a forged ticket, a delete the work did not
 * delegate, and a read outside the report's goal. AC-4b: the editable case ({@link DelegationChoice#EDITABLE_CASE}) with
 * each of its 3 x 3 x 2 delegation choices on the three paths, so 54 more: 69 in all. The paths are the names the operator
 * route takes ({@code OAUTH2_DELEGATED}, {@code OAUTH2_AGENT}, {@code SESSION};
 * {@link io.contexa.showcase.portal.scenario.AgentPaths}).
 */
public final class AgentMenu {

    /** The menu's cases without a choice, in the order the visitor is shown them. */
    public static final List<String> CASES = List.of("M19A", "M19N", "M14A", "M16A", "M13A");

    /** The paths, in the order the visitor is shown them. */
    public static final List<String> PATHS = List.of("OAUTH2_DELEGATED", "OAUTH2_AGENT", "SESSION");

    /**
     * One combination of the table.
     *
     * @param choice the delegation choice of the editable case; null for a case without one
     */
    public record Combo(String caseKey, String path, DelegationChoice choice) {

        /** A combination without a choice. */
        public Combo(String caseKey, String path) {
            this(caseKey, path, null);
        }

        /** The choice in one word, empty for a combination without one. */
        public String choiceKey() {
            return choice == null ? "" : choice.key();
        }
    }

    private AgentMenu() {
    }

    /** Every combination: the five cases path by path, then the editable case's choices path by path. */
    public static List<Combo> combos() {
        List<Combo> combos = new ArrayList<>();
        for (String key : CASES) {
            for (String path : PATHS) {
                combos.add(new Combo(key, path));
            }
        }
        for (DelegationChoice choice : DelegationChoice.every()) {
            for (String path : PATHS) {
                combos.add(new Combo(DelegationChoice.EDITABLE_CASE, path, choice));
            }
        }
        return List.copyOf(combos);
    }

    /** Whether the table holds the combination: a case with no choice, or the editable case with a full choice. */
    public static boolean has(String caseKey, String path, DelegationChoice choice) {
        if (!PATHS.contains(path)) {
            return false;
        }
        if (DelegationChoice.EDITABLE_CASE.equals(caseKey)) {
            return choice != null && choice.quantity() != null && choice.period() != null && choice.operations() != null;
        }
        return CASES.contains(caseKey) && choice == null;
    }

    public static boolean has(String caseKey, String path) {
        return has(caseKey, path, null);
    }
}
