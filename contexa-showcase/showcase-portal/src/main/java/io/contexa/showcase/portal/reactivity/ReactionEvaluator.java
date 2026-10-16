package io.contexa.showcase.portal.reactivity;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.portal.benchmark.BenchmarkService;
import io.contexa.showcase.portal.benchmark.BenchmarkView;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;

/**
 * W6-1 (P6-CHANGE-2, plan 8.5, metric A4): the reaction check. Every variant of the reaction matrix (resource
 * reactivity/reaction-matrix.json, the canon is docs/showcase/프롬프트-반응행렬.md) carries the minimum-action rules and
 * the direction written before the runs; the employee and operation variants change the whole baseline or the policy
 * family, so their expectation is computed from the run's own sealed facts with the same function before the answer
 * is read (P0-CHANGE-19). The function is the prototype's (prompt-audit/w06/refcalc.apply_rules and
 * reaction_full.expectation) on the fact lines the model received: P1 a sensitive class with two unexplained identity
 * deviations, P2 a sensitive export with the device or the network unexplained, P3 the policy not satisfied. Only the
 * steps with a seal are read (a step decided by an earlier decision has no prompt of its own). The engine's own
 * findings are compared with these rules as a cross-check, not used as the expectation.
 */
public final class ReactionEvaluator {

    public static final String AT_LEAST_CHALLENGE = "AT_LEAST_CHALLENGE";
    public static final String ALLOW = "ALLOW";
    public static final String MODEL_JUDGES = "MODEL_JUDGES";

    private static final List<String> ACTION_ORDER = List.of("ALLOW", "CHALLENGE", "ESCALATE", "BLOCK");
    private static final Set<String> IDENTITY = Set.of("time", "day", "network", "device");
    private static final List<String> DIMENSIONS = List.of("login method", "time", "day", "network", "device",
            "target", "action", "class", "size", "rate");
    private static final double CONSISTENT = 0.95;

    private final Map<String, Variant> byLabel;

    ReactionEvaluator(List<Variant> variants) {
        Map<String, Variant> labels = new LinkedHashMap<>();
        variants.forEach(variant -> labels.put(variant.label(), variant));
        this.byLabel = Map.copyOf(labels);
    }

    /**
     * One variant of the matrix: planned rows carry the rules, the steps they hit and the direction; the others are
     * computed from the run. Lab rows carry the conditions the harness sends, case-definition rows their variant key.
     */
    public record Variant(String label, String base, String condition, String value, boolean planned,
                          List<String> rules, List<Integer> ruleSteps, String expectedDirection,
                          Map<String, Object> conditions, String variantKey) {
    }

    /** A minimum-action finding the engine recorded with a decision: rule, required and decided action. */
    public record Finding(String rule, String requiredAction, String decidedAction, boolean violated) {
    }

    /** One step of a run: its final action, the engine's findings and the sealed facts (null without a seal). */
    public record Step(int stepNo, String finalAction, List<Finding> findings, PromptFacts facts) {
    }

    /** The rules, the steps they hit and the direction of a run's own facts. */
    public record Expectation(List<String> rules, List<Integer> ruleSteps, String direction, List<String> unexplained) {
    }

    /** One run judged against its variant. */
    public record RunReaction(String runId, String label, Expectation planned, Expectation run, Boolean planMatchesRun,
                              boolean engineAgrees, String expectedDirection, String strongest,
                              boolean ruleStepsPresent, boolean minimumViolation, int decidedBelowMinimum,
                              Boolean directionAgrees) {
    }

    /**
     * The batch: minimum actions kept over runs with a rule step (plan: violations 0), the direction agreement over the
     * scored runs (plan: at least 95%), the runs agreeing with their variant's most frequent action over repeated
     * variants (plan: at least 95%), and the variants and runs to look at.
     */
    public record Summary(int runs, int notInMatrix, BenchmarkView.Rate minimumKept, BenchmarkView.Rate direction,
                          BenchmarkView.Rate consistency, List<String> consistencyBelow95,
                          List<String> planMismatches, List<String> engineDisagreements, List<RunReaction> results) {
    }

    public static ReactionEvaluator fromResources() {
        try (InputStream stream = ReactionEvaluator.class.getResourceAsStream("/reactivity/reaction-matrix.json")) {
            if (stream == null) {
                throw new IllegalStateException("reactivity/reaction-matrix.json is missing");
            }
            ObjectMapper json = new ObjectMapper();
            List<Variant> variants = new ArrayList<>();
            for (JsonNode row : json.readTree(stream).path("variants")) {
                List<String> rules = row.path("rules").isArray()
                        ? json.convertValue(row.path("rules"), json.getTypeFactory()
                        .constructCollectionType(List.class, String.class)) : null;
                List<Integer> steps = row.path("ruleSteps").isArray()
                        ? json.convertValue(row.path("ruleSteps"), json.getTypeFactory()
                        .constructCollectionType(List.class, Integer.class)) : null;
                Map<String, Object> conditions = row.path("conditions").isObject()
                        ? json.convertValue(row.path("conditions"), json.getTypeFactory()
                        .constructMapType(LinkedHashMap.class, String.class, Object.class)) : null;
                variants.add(new Variant(row.path("label").asText(), row.path("base").asText(),
                        row.path("condition").asText(), row.path("value").asText(), row.path("planned").asBoolean(),
                        rules, steps, row.path("expectedDirection").asText(null), conditions,
                        row.path("variantKey").asText(null)));
            }
            return new ReactionEvaluator(variants);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public Collection<Variant> variants() {
        return byLabel.values();
    }

    public Optional<Variant> variant(String label) {
        return Optional.ofNullable(byLabel.get(label));
    }

    public Optional<Variant> variantOfKey(String variantKey) {
        return byLabel.values().stream().filter(variant -> Objects.equals(variant.variantKey(), variantKey))
                .findFirst();
    }

    public RunReaction judge(String runId, String label, List<Step> steps) {
        Variant variant = byLabel.get(label);
        if (variant == null) {
            throw new IllegalArgumentException("Not a variant of the reaction matrix: " + label);
        }
        Expectation own = expectation(steps);
        Expectation planned = variant.planned()
                ? new Expectation(List.copyOf(variant.rules()), List.copyOf(variant.ruleSteps()),
                variant.expectedDirection(), List.of()) : null;
        Set<String> engineRules = new TreeSet<>();
        int below = 0;
        for (Step step : steps) {
            for (Finding finding : step.findings()) {
                engineRules.add(ruleOf(finding.rule()));
                if (finding.violated()) {
                    below++;
                }
            }
        }
        String strongest = steps.stream().map(Step::finalAction).filter(Objects::nonNull)
                .max(Comparator.comparingInt(ReactionEvaluator::rank)).orElse(null);
        boolean violation = false;
        for (Step step : steps) {
            if (!own.ruleSteps().contains(step.stepNo())) {
                continue;
            }
            if (step.finalAction() != null && rank(step.finalAction()) < rank(required(step))) {
                violation = true;
            }
        }
        String direction = planned != null ? planned.direction() : own.direction();
        Boolean agrees = null;
        if (AT_LEAST_CHALLENGE.equals(direction)) {
            agrees = strongest != null && rank(strongest) >= rank("CHALLENGE");
        } else if (ALLOW.equals(direction)) {
            agrees = ALLOW.equals(strongest);
        }
        return new RunReaction(runId, label, planned, own,
                planned == null ? null : planned.rules().equals(own.rules()),
                List.copyOf(engineRules).equals(own.rules()), direction, strongest, !own.ruleSteps().isEmpty(),
                violation, below, agrees);
    }

    public Summary summarise(List<RunReaction> reactions, int notInMatrix) {
        List<RunReaction> withRules = reactions.stream().filter(RunReaction::ruleStepsPresent).toList();
        long kept = withRules.stream().filter(reaction -> !reaction.minimumViolation()).count();
        List<RunReaction> scored = reactions.stream().filter(reaction -> reaction.directionAgrees() != null).toList();
        long agreeing = scored.stream().filter(RunReaction::directionAgrees).count();
        Map<String, List<String>> byVariant = new LinkedHashMap<>();
        for (RunReaction reaction : reactions) {
            if (reaction.strongest() != null) {
                byVariant.computeIfAbsent(reaction.label(), key -> new ArrayList<>()).add(reaction.strongest());
            }
        }
        long repeatedRuns = 0;
        long modeRuns = 0;
        List<String> below = new ArrayList<>();
        for (Map.Entry<String, List<String>> entry : byVariant.entrySet()) {
            List<String> actions = entry.getValue();
            if (actions.size() < 2) {
                continue;
            }
            long mode = actions.stream().distinct()
                    .mapToLong(action -> actions.stream().filter(action::equals).count()).max().orElse(0);
            repeatedRuns += actions.size();
            modeRuns += mode;
            if ((double) mode / actions.size() < CONSISTENT) {
                below.add(entry.getKey());
            }
        }
        List<String> mismatches = reactions.stream().filter(reaction -> Boolean.FALSE.equals(reaction.planMatchesRun()))
                .map(RunReaction::label).distinct().toList();
        List<String> disagreements = reactions.stream().filter(reaction -> !reaction.engineAgrees())
                .map(RunReaction::label).distinct().toList();
        return new Summary(reactions.size(), notInMatrix, BenchmarkService.rate(kept, withRules.size()),
                BenchmarkService.rate(agreeing, scored.size()), BenchmarkService.rate(modeRuns, repeatedRuns),
                List.copyOf(below), mismatches, disagreements, List.copyOf(reactions));
    }

    /** The rules, rule steps and direction of the sealed steps of a run (reaction_full.expectation). */
    static Expectation expectation(List<Step> steps) {
        Set<String> rules = new TreeSet<>();
        Set<String> unexplainedAll = new TreeSet<>();
        List<Integer> ruleSteps = new ArrayList<>();
        boolean claimFalse = false;
        boolean allSatisfiedAndExplained = true;
        int judged = 0;
        for (Step step : steps) {
            if (step.facts() == null) {
                continue;
            }
            judged++;
            Set<String> unexplained = unexplained(step.facts());
            unexplainedAll.addAll(unexplained);
            String resourceClass = first(step.facts(), "ResourceClass");
            boolean sensitive = resourceClass != null
                    && (resourceClass.startsWith("SENSITIVE") || resourceClass.startsWith("CRITICAL"));
            String action = first(step.facts(), "Action");
            boolean export = action != null && action.startsWith("EXPORT");
            String satisfied = first(step.facts(), "PolicySatisfied");
            List<String> stepRules = new ArrayList<>();
            if (sensitive && unexplained.stream().filter(IDENTITY::contains).count() >= 2) {
                stepRules.add("P1");
            }
            if (sensitive && export && (unexplained.contains("device") || unexplained.contains("network"))) {
                stepRules.add("P2");
            }
            if (satisfied != null && satisfied.startsWith("no")) {
                stepRules.add("P3");
            }
            if (!stepRules.isEmpty()) {
                rules.addAll(stepRules);
                ruleSteps.add(step.stepNo());
            }
            claimFalse |= step.facts().values().getOrDefault("Ticket", List.of()).stream()
                    .anyMatch(value -> value.contains("named by the requester does not exist"));
            allSatisfiedAndExplained &= satisfied != null && satisfied.startsWith("yes") && unexplained.isEmpty();
        }
        String direction;
        if (!rules.isEmpty()) {
            direction = AT_LEAST_CHALLENGE;
        } else if (claimFalse) {
            // A claimed ticket that does not exist is a deceptive act the rules do not grade: the model judges it.
            direction = MODEL_JUDGES;
        } else if (judged > 0 && allSatisfiedAndExplained) {
            direction = ALLOW;
        } else {
            direction = MODEL_JUDGES;
        }
        return new Expectation(List.copyOf(rules), List.copyOf(ruleSteps), direction, List.copyOf(unexplainedAll));
    }

    /** The dimensions DeviationsFromBaseline marks unexplained: "time 03 seen 0 of 22 (unexplained); ...". */
    static Set<String> unexplained(PromptFacts facts) {
        Set<String> dimensions = new TreeSet<>();
        for (String value : facts.values().getOrDefault("DeviationsFromBaseline", List.of())) {
            int arrow = value.indexOf("->");
            for (String part : (arrow >= 0 ? value.substring(arrow + 2) : value).split(";")) {
                String segment = part.trim();
                if (!segment.contains("(unexplained)")) {
                    continue;
                }
                DIMENSIONS.stream().filter(dimension -> segment.startsWith(dimension + " ")).findFirst()
                        .ifPresent(dimensions::add);
            }
        }
        return dimensions;
    }

    /** The least action of a step: CHALLENGE, or the engine's recorded floor of its rule when that is higher (P3). */
    private static String required(Step step) {
        String required = "CHALLENGE";
        for (Finding finding : step.findings()) {
            if (finding.requiredAction() != null && rank(finding.requiredAction()) > rank(required)) {
                required = finding.requiredAction();
            }
        }
        return required;
    }

    private static String first(PromptFacts facts, String label) {
        List<String> values = facts.values().get(label);
        return values == null || values.isEmpty() ? null : values.get(0);
    }

    /** P1_IDENTITY_DEVIATION becomes P1, the matrix's name of the rule. */
    private static String ruleOf(String engineRule) {
        int end = engineRule.indexOf('_');
        return (end > 0 ? engineRule.substring(0, end) : engineRule).toUpperCase(Locale.ROOT);
    }

    private static int rank(String action) {
        return ACTION_ORDER.indexOf(action.trim().toUpperCase(Locale.ROOT));
    }
}
