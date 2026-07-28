package io.contexa.contexacore.verification.runtime.prompt;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.metric.OfficialMetricEvaluationResult;
import io.contexa.contexacore.verification.runtime.OfficialVerificationMessageResolver;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

public class FinalPromptMetricEvaluationSuite {

    private final FinalPromptParser parser;
    private final ObjectMapper objectMapper;
    private final FinalPromptPreflightService preflightService;
    private final FinalPromptMetricContractCatalog contractCatalog;
    private final Map<String, FinalPromptMetricEvaluator> evaluators;
    private final OfficialVerificationMessageResolver messageResolver;

    public FinalPromptMetricEvaluationSuite(ObjectMapper objectMapper) {
        this(objectMapper, OfficialVerificationMessageResolver.classpath(Locale.KOREAN));
    }

    public FinalPromptMetricEvaluationSuite(
            ObjectMapper objectMapper,
            OfficialVerificationMessageResolver messageResolver) {
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper");
        this.messageResolver = Objects.requireNonNull(messageResolver, "messageResolver");
        this.preflightService = new FinalPromptPreflightService(this.objectMapper, this.messageResolver);
        this.contractCatalog = FinalPromptMetricContractCatalog.load(this.objectMapper);
        this.parser = new FinalPromptParser(contractCatalog);
        this.evaluators = buildEvaluators(contractCatalog);
    }

    public Map<String, OfficialMetricEvaluationResult> evaluatePromptQuality(
            SealedEvidencePackage evidencePackage) {
        FinalPromptPreflightResult preflight = preflightService.verify(evidencePackage);
        if (!preflight.ready()) {
            preflightService.assertReady(evidencePackage);
        }
        FinalPromptEvaluationInput input = FinalPromptEvaluationInput.from(
                evidencePackage, parser, preflight, objectMapper);
        FinalPromptMetricEvaluationContext context = new FinalPromptMetricEvaluationContext(input);
        Map<String, OfficialMetricEvaluationResult> results = new LinkedHashMap<>();
        for (String metricCode : contractCatalog.metricCodesInOrder()) {
            FinalPromptMetricEvaluator evaluator = evaluators.get(metricCode);
            if (evaluator == null) {
                throw new IllegalStateException("Final prompt metric evaluator is missing: " + metricCode);
            }
            FinalPromptMetricResult result = evaluator.evaluate(context);
            if (result == null) {
                throw new IllegalStateException("Final prompt metric evaluator returned null: " + metricCode);
            }
            results.put(metricCode, result.toOfficialMetricResult());
        }
        return Map.copyOf(results);
    }

    public FinalPromptPreflightResult verifyPreflight(SealedEvidencePackage evidencePackage) {
        return preflightService.verify(evidencePackage);
    }

    private Map<String, FinalPromptMetricEvaluator> buildEvaluators(FinalPromptMetricContractCatalog catalog) {
        Map<String, FinalPromptMetricEvaluator> result = new LinkedHashMap<>();
        FinalPromptMetricRuleEngine ruleEngine = new FinalPromptMetricRuleEngine();
        for (String metricCode : catalog.metricCodesInOrder()) {
            FinalPromptMetricEvaluator evaluator = new ContractBackedFinalPromptMetricEvaluator(
                    catalog.metric(metricCode), ruleEngine, catalog, messageResolver);
            result.put(evaluator.metricCode(), evaluator);
        }
        return Map.copyOf(result);
    }
}
