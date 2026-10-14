package io.contexa.contexacore.autonomous.tiered.prompt;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.components.prompt.PromptBudgetProfile;
import io.contexa.contexacore.verification.evidence.CanonicalSecurityContextSerializer;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageIntegrity;
import io.contexa.contexacore.verification.inspection.SealIntegrityCheck;
import io.contexa.contexacore.verification.inspection.PromptInspector;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.GZIPInputStream;

/**
 * The v20 renders of the golden cases as the sealed packages the prompt inspector reads: the user prompt the model got
 * and the canonical context the render used (decision facts with their drawn ids), as the assembler seals them.
 */
final class InspectionGolden {

    static final ObjectMapper JSON = new ObjectMapper().findAndRegisterModules();
    static final CanonicalSecurityContextSerializer SERIALIZER = new CanonicalSecurityContextSerializer(JSON);
    private static final SealedEvidencePackageIntegrity INTEGRITY = new SealedEvidencePackageIntegrity();
    /** The fact id the renderer draws before a line a reason code may cite (dictionary 1.5): {@code [R3] }. */
    private static final Pattern FACT_ID = Pattern.compile("^\\[[BSRFP]\\d+] ");

    private static List<Render> renders;

    private InspectionGolden() {
    }

    /** One v20 render of a golden case and profile. */
    record Render(String caseKey, PromptBudgetProfile profile, String systemPrompt, String userPrompt,
                  CanonicalSecurityContext used, Map<String, Object> executionMetadata, String ragResultsJson,
                  String requestFactsJson) {

        SealedEvidencePackage sealed() {
            return sealed(userPrompt);
        }

        /**
         * The package the assembler seals when the model got this user prompt: the render's sources and execution
         * metadata, the prompts with their hashes, a correlation id and the package hash.
         */
        SealedEvidencePackage sealed(String userPromptText) {
            SealedEvidencePackage sealed = InspectionGolden.sealed(userPromptText, SERIALIZER.serialize(used));
            sealed.setRagResultsJson(ragResultsJson);
            // The request facts the render's event was built from, as the assembler seals them (R1b-7).
            sealed.setRequestFactsJson(requestFactsJson);
            // The correlation id is the request id the sealed request facts name, as the assembler seals it (R1b-9).
            sealed.setCorrelationId(requestId(requestFactsJson, "golden-" + caseKey + "-" + profile));
            sealed.setSystemPromptText(systemPrompt);
            sealed.setRawSystemPrompt(systemPrompt);
            Map<String, Object> metadata = new LinkedHashMap<>(executionMetadata);
            metadata.put("promptHash", SealIntegrityCheck.sha256(systemPrompt + "\n---\n" + userPromptText));
            try {
                sealed.setPromptExecutionMetadataJson(JSON.writeValueAsString(metadata));
            }
            catch (Exception exception) {
                throw new IllegalStateException(exception);
            }
            sealed.setPromptHash(String.valueOf(metadata.get("promptHash")));
            sealed.setSystemPromptHash(SealIntegrityCheck.sha256(systemPrompt));
            sealed.setRawSystemPromptHash(SealIntegrityCheck.sha256(systemPrompt));
            sealed.setUserPromptHash(SealIntegrityCheck.sha256(userPromptText));
            sealed.setRawUserPromptHash(SealIntegrityCheck.sha256(userPromptText));
            sealed.setPackageHash(INTEGRITY.computeHash(sealed));
            return sealed;
        }
    }

    /** The request id the sealed request facts name, else the given id. */
    private static String requestId(String requestFactsJson, String otherwise) {
        try {
            JsonNode facts = requestFactsJson != null ? JSON.readTree(requestFactsJson) : null;
            return facts != null && facts.hasNonNull("requestId") ? facts.get("requestId").asText() : otherwise;
        }
        catch (IOException exception) {
            throw new UncheckedIOException(exception);
        }
    }

    static synchronized List<Render> renders() {
        if (renders == null) {
            SecurityDecisionGoldenRender golden = SecurityDecisionGoldenRender.load();
            TieredStrategyProperties properties = new TieredStrategyProperties();
            properties.getPromptBundle().setActive(SecurityDecisionPromptBundles.V20.version());
            List<Render> all = new ArrayList<>();
            for (JsonNode goldenCase : golden.cases()) {
                for (PromptBudgetProfile profile : SecurityDecisionGoldenRender.PROFILES) {
                    SecurityDecisionGoldenRender.RenderedCase rendered = golden.render(goldenCase, profile, properties);
                    // The golden inputs keep the sealed retrieval summary the render's documents were rebuilt from.
                    all.add(new Render(rendered.caseKey(), profile, rendered.systemText(), rendered.userText(),
                            rendered.canonicalContext(), rendered.executionMetadata().toMetadataMap(),
                            goldenCase.path("ragResults").toString(), goldenCase.path("requestFacts").toString()));
                }
            }
            renders = List.copyOf(all);
        }
        return renders;
    }

    /** The drawn line without the fact id drawn before it, if any. */
    static String bare(String line) {
        return FACT_ID.matcher(line).replaceFirst("");
    }

    /** The fact id drawn before the line with its space, or an empty text when the line carries none. */
    static String factIdOf(String line) {
        Matcher matcher = FACT_ID.matcher(line);
        return matcher.find() ? matcher.group() : "";
    }

    /** The entry label of a drawn line, without its fact id. */
    static String labelOf(String line) {
        String bare = bare(line);
        return bare.substring(0, bare.indexOf(": "));
    }

    /** Whether a line of the prompt starts with the text once its fact id is set aside. */
    static boolean hasLine(String userPrompt, String start) {
        return Arrays.stream(userPrompt.split("\n")).anyMatch(line -> bare(line).startsWith(start));
    }

    /** The first line of the prompt starting with the text once its fact id is set aside, as it was drawn. */
    static String lineStarting(String userPrompt, String start) {
        return Arrays.stream(userPrompt.split("\n")).filter(line -> bare(line).startsWith(start)).findFirst()
                .orElseThrow();
    }

    static Render render(Predicate<String> wanted) {
        return renders().stream().filter(render -> wanted.test(render.userPrompt())).findFirst()
                .orElseThrow(() -> new IllegalStateException("no golden render has the wanted lines"));
    }

    /** The v20 render of the base render's golden case and profile after a change to the case's canonical context. */
    static Render renderWith(Render base, Consumer<CanonicalSecurityContext> change) {
        SecurityDecisionGoldenRender golden = SecurityDecisionGoldenRender.load();
        JsonNode goldenCase = golden.cases().stream()
                .filter(node -> base.caseKey().equals(node.path("caseKey").asText())).findFirst().orElseThrow();
        CanonicalSecurityContext context = SERIALIZER.deserialize(goldenCase.path("canonicalContext").toString());
        change.accept(context);
        ObjectNode changed = goldenCase.deepCopy();
        try {
            changed.set("canonicalContext", JSON.readTree(SERIALIZER.serialize(context)));
        }
        catch (IOException exception) {
            throw new UncheckedIOException(exception);
        }
        TieredStrategyProperties properties = new TieredStrategyProperties();
        properties.getPromptBundle().setActive(SecurityDecisionPromptBundles.V20.version());
        SecurityDecisionGoldenRender.RenderedCase rendered = golden.render(changed, base.profile(), properties);
        return new Render(rendered.caseKey(), base.profile(), rendered.systemText(), rendered.userText(),
                rendered.canonicalContext(), rendered.executionMetadata().toMetadataMap(),
                goldenCase.path("ragResults").toString(), goldenCase.path("requestFacts").toString());
    }

    /**
     * Real v20 packages the showcase engine sealed under the current bundle (read from its database on 2026-10-14,
     * bundle 2026.10.14-v20.13: A3T 6480, A8 6481, S08 6482): the prompt the model got with the sources sealed with it,
     * as the inspector reads them from the package table.
     */
    static List<SealedEvidencePackage> showcaseSealed() {
        return showcaseSealed("prompt-inspection/showcase-v20-sealed.json.gz");
    }

    /**
     * Real v20 packages the showcase engine sealed under an earlier bundle (W3-13 build on 2026-10-12, bundle
     * 2026.10.11-v19.8 drawn in the v20 layout): their dictionary is not this build's (R1b-7).
     */
    static List<SealedEvidencePackage> showcaseSealedOfAnEarlierBundle() {
        return showcaseSealed("prompt-inspection/showcase-v20-sealed-earlier-bundle.json.gz");
    }

    private static List<SealedEvidencePackage> showcaseSealed(String resource) {
        try (InputStream input = InspectionGolden.class.getClassLoader().getResourceAsStream(resource)) {
            if (input == null) {
                throw new IllegalStateException("Showcase sealed packages are missing");
            }
            JsonNode rows;
            try (GZIPInputStream gzip = new GZIPInputStream(input)) {
                rows = JSON.readTree(gzip.readAllBytes());
            }
            List<SealedEvidencePackage> packages = new ArrayList<>();
            for (JsonNode row : rows) {
                packages.add(SealedEvidencePackage.builder()
                        .packageId(row.path("package_id").asText())
                        .correlationId(row.path("correlation_id").asText())
                        .userPromptText(row.path("user_prompt_text").asText())
                        .rawUserPrompt(row.path("raw_user_prompt").asText())
                        .canonicalContextJson(row.path("canonical_context_json").asText())
                        .promptExecutionMetadataJson(row.path("prompt_execution_metadata_json").asText())
                        .authStateJson(row.path("auth_state_json").asText())
                        .requestFactsJson(row.path("request_facts_json").asText())
                        .ragResultsJson(row.path("rag_results_json").asText())
                        .build());
            }
            return packages;
        }
        catch (IOException exception) {
            throw new UncheckedIOException(exception);
        }
    }

    static SealedEvidencePackage sealed(String userPrompt, String canonicalContextJson) {
        try {
            return SealedEvidencePackage.builder()
                    .packageId("golden")
                    .rawUserPrompt(userPrompt)
                    .userPromptText(userPrompt)
                    .canonicalContextJson(canonicalContextJson)
                    .promptExecutionMetadataJson(JSON.writeValueAsString(Map.of("governanceDescriptor",
                            Map.of("userPromptLayoutVersion", PromptInspector.V20_LAYOUT,
                                    "promptKey", "cortex.security-decision",
                                    "promptBundleVersion", SecurityDecisionPromptBundles.V20.descriptor().promptVersion()))))
                    .build();
        }
        catch (Exception exception) {
            throw new IllegalStateException(exception);
        }
    }
}
