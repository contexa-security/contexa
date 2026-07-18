package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexaiam.admin.promptquality.official.model.OfficialActualPromptProblem;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

final class OfficialVerificationRemediationGroupRecorder {

    private final OfficialVerificationRemediationGroupWriter writer;
    private final OfficialActualPromptProblemNarrative problemNarrative;
    private final OfficialVerificationMetricNarrative metricNarrative;
    private final OfficialVerificationCustomerTextPolicy customerText;

    OfficialVerificationRemediationGroupRecorder(
            OfficialVerificationRemediationGroupWriter writer,
            OfficialActualPromptProblemNarrative problemNarrative,
            OfficialVerificationMetricNarrative metricNarrative,
            OfficialVerificationCustomerTextPolicy customerText) {
        this.writer = writer;
        this.problemNarrative = problemNarrative;
        this.metricNarrative = metricNarrative;
        this.customerText = customerText;
    }

    void record(
            String aggregateRunId,
            String packageId,
            String certificateId,
            String caseId,
            List<OfficialActualPromptProblem> problems) {
        Map<String, GroupAccumulator> groups = new LinkedHashMap<>();
        for (OfficialActualPromptProblem problem : safeList(problems)) {
            if (problem == null || !"BLOCKING".equals(normalize(problem.severity()))) {
                continue;
            }
            String owner = firstNonBlank(
                    problem.remediationOwner(),
                    problemNarrative.message("enterprise.pqa.officialNarrative.owner.official"));
            String failureType = firstNonBlank(
                    problem.problemType(), problem.fieldKey(), "PROMPT_FIELD_CONTRACT");
            String nextAction = problemNarrative.action(problem);
            String key = normalize(owner) + "|" + normalize(failureType) + "|" + normalize(nextAction);
            groups.computeIfAbsent(key, ignored -> new GroupAccumulator(
                    owner, failureType, nextAction, problem, problemNarrative)).add(problem);
        }
        groups.values().forEach(group -> writer.insert(command(
                aggregateRunId, packageId, certificateId, caseId, group)));
    }

    private OfficialVerificationRemediationGroupWriter.RemediationGroupCommand command(
            String aggregateRunId,
            String packageId,
            String certificateId,
            String caseId,
            GroupAccumulator group) {
        return new OfficialVerificationRemediationGroupWriter.RemediationGroupCommand(
                new OfficialVerificationRemediationGroupWriter.GroupIdentity(
                        aggregateRunId, packageId, certificateId, caseId),
                new OfficialVerificationRemediationGroupWriter.GroupClassification(
                        group.failureType, group.metricCodes(), group.checkCodes(), group.findingCount,
                        "OFFICIAL_VERIFICATION", group.comparisonFieldKeys(), group.promptLocations()),
                new OfficialVerificationRemediationGroupWriter.GroupNarrative(
                        customerText.require("remediationGroup.remediationOwner",
                                metricNarrative.ownerDisplayName(group.owner)),
                        customerText.require("remediationGroup.operatorTitle", group.title()),
                        customerText.require("remediationGroup.operatorReason", group.reason()),
                        customerText.require("remediationGroup.nextAction", group.nextAction),
                        customerText.require("remediationGroup.reverifyCriterion", group.reverifyCriterion)));
    }

    private String firstNonBlank(String... values) {
        for (String value : values) {
            if (StringUtils.hasText(value)) {
                return value.trim();
            }
        }
        return "";
    }

    private String normalize(String value) {
        return value == null ? "" : value.trim().toUpperCase(Locale.ROOT);
    }

    private <T> List<T> safeList(List<T> values) {
        return values == null ? List.of() : values;
    }

    private static final class GroupAccumulator {
        private final String owner;
        private final String failureType;
        private final String nextAction;
        private final String firstReason;
        private final String firstLabel;
        private final List<String> metricCodes = new ArrayList<>();
        private final List<String> checkCodes = new ArrayList<>();
        private final List<String> comparisonFieldKeys = new ArrayList<>();
        private final List<String> promptLocations = new ArrayList<>();
        private String reverifyCriterion;
        private int findingCount;

        private GroupAccumulator(
                String owner,
                String failureType,
                String nextAction,
                OfficialActualPromptProblem firstProblem,
                OfficialActualPromptProblemNarrative narrative) {
            this.owner = owner;
            this.failureType = failureType;
            this.nextAction = nextAction;
            this.firstReason = narrative.rootCause(firstProblem);
            this.firstLabel = narrative.title(firstProblem);
            this.reverifyCriterion = narrative.reverify(firstProblem);
        }

        private void add(OfficialActualPromptProblem problem) {
            if (problem == null) {
                return;
            }
            problem.metricCodes().forEach(code -> addUnique(metricCodes, code));
            addUnique(checkCodes, problem.problemId());
            addUnique(comparisonFieldKeys, problem.fieldKey());
            addUnique(promptLocations, problem.promptSection());
            findingCount++;
        }

        private String title() {
            if (!StringUtils.hasText(firstLabel)) {
                throw new IllegalStateException(
                        "ENGINE_CONTRACT_ERROR: Remediation group is missing contract title. failureType=" + failureType);
            }
            return firstLabel.trim();
        }

        private String reason() {
            if (!StringUtils.hasText(firstReason)) {
                throw new IllegalStateException(
                        "ENGINE_CONTRACT_ERROR: Remediation group is missing contract reason. failureType=" + failureType);
            }
            return firstReason.trim();
        }

        private String metricCodes() { return String.join(",", metricCodes); }
        private String checkCodes() { return String.join(",", checkCodes); }
        private String comparisonFieldKeys() { return String.join(",", comparisonFieldKeys); }
        private String promptLocations() { return String.join(",", promptLocations); }

        private static void addUnique(List<String> values, String value) {
            if (StringUtils.hasText(value) && !values.contains(value.trim())) {
                values.add(value.trim());
            }
        }
    }
}
