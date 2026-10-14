/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexacore.verification.inspection;

import io.contexa.contexacore.std.components.prompt.PromptGovernanceSupport;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageIntegrity;

import java.util.Map;

/**
 * Whether the sealed package can be trusted as the record of what the model got: the package hash still covers every
 * sealed field, the system and user prompts were captured and match their hashes (the prompt hash is the one the
 * render's metadata computes over {@code system \n---\n user}), the prompt the model got is the rendered one or the
 * difference is recorded (compression or layout-only normalization), and the request and correlation ids are there to
 * trace it. Runs on every layout.
 */
public final class SealIntegrityCheck implements PromptInspectionCheck {

    public static final String CODE = "SEAL_INTEGRITY";

    private static final String PACKAGE = "sealedPackage.";

    private final SealedEvidencePackageIntegrity integrity;

    public SealIntegrityCheck() {
        this.integrity = new SealedEvidencePackageIntegrity();
    }

    @Override
    public String code() {
        return CODE;
    }

    @Override
    public boolean dictionaryPromptOnly() {
        return false;
    }

    @Override
    public void inspect(PromptInspectionTally tally) {
        SealedEvidencePackage sealed = tally.subject().evidencePackage();
        Map<String, Object> metadata = tally.subject().executionMetadata();
        packageHash(tally, sealed);
        for (String source : tally.subject().unreadSources()) {
            tally.unverifiable(tally.unverifiableFinding().entry(source).sourceRef(PACKAGE + source)
                    .reason("the sealed source does not read, so what is drawn from it is not compared").build());
        }
        String system = sealed.getSystemPromptText();
        String user = sealed.getUserPromptText();
        boolean captured = hasText(system) && hasText(user);
        record(tally, captured, "prompts", "system and user prompts", captured ? "captured" : "missing",
                PACKAGE + "userPromptText", "the prompts the model got are not both sealed");
        hash(tally, "promptHash", firstText(sealed.getPromptHash(), text(metadata.get("promptHash"))),
                sha256(PromptGovernanceSupport.combinedPrompt(text(system), text(user))));
        hash(tally, "systemPromptHash", sealed.getSystemPromptHash(), sha256(text(system)));
        hash(tally, "userPromptHash", sealed.getUserPromptHash(), sha256(text(user)));
        hash(tally, "rawSystemPromptHash", sealed.getRawSystemPromptHash(), sha256(text(sealed.getRawSystemPrompt())));
        hash(tally, "rawUserPromptHash", sealed.getRawUserPromptHash(), sha256(text(sealed.getRawUserPrompt())));
        parity(tally, sealed, metadata);
        trace(tally, sealed.getCorrelationId());
    }

    private void packageHash(PromptInspectionTally tally, SealedEvidencePackage sealed) {
        SealedEvidencePackageIntegrity.Status status = integrity.evaluate(sealed);
        switch (status) {
            case VERIFIED -> tally.matched();
            case MISMATCH -> tally.mismatch(tally.mismatchFinding().entry("packageHash").sourceRef(PACKAGE + "packageHash")
                    .expected(sealed.getPackageHash()).actual(integrity.computeHash(sealed))
                    .reason("the sealed package changed after it was sealed").build());
            case UNVERIFIABLE -> tally.unverifiable(tally.unverifiableFinding().entry("packageHash")
                    .sourceRef(PACKAGE + "packageHash")
                    .reason("the package carries no package hash, or a sealed prompt has no hash").build());
        }
    }

    private static void hash(PromptInspectionTally tally, String name, String declared, String recomputed) {
        if (!hasText(declared)) {
            tally.unverifiable(tally.unverifiableFinding().entry(name).sourceRef(PACKAGE + name)
                    .actual(recomputed).reason("the package carries no " + name).build());
            return;
        }
        record(tally, declared.equals(recomputed), name, declared, recomputed, PACKAGE + name,
                "the " + name + " does not match the sealed prompt");
    }

    /** The prompt the model got is the rendered one, or the difference is recorded. */
    private static void parity(PromptInspectionTally tally, SealedEvidencePackage sealed, Map<String, Object> metadata) {
        boolean same = normalized(sealed.getRawSystemPrompt()).equals(normalized(sealed.getSystemPromptText()))
                && normalized(sealed.getRawUserPrompt()).equals(normalized(sealed.getUserPromptText()));
        boolean recorded = Boolean.TRUE.equals(metadata.get("promptCompressionApplied"));
        record(tally, same || recorded, "rawUserPrompt", "the same prompt, or a recorded compression",
                same ? "same" : "different, no recorded reason", PACKAGE + "rawUserPrompt",
                "the prompt the model got differs from the rendered prompt without a recorded reason");
    }

    /**
     * R1b-9: the package is traced by its correlation id, the request's id, and the request facts sealed with it name
     * the same request (the assembler writes the request id, else the correlation id). Request facts that do not read
     * are named once already (R1b-5).
     */
    private static void trace(PromptInspectionTally tally, String correlationId) {
        if (!hasText(correlationId)) {
            record(tally, false, "requestId", "the request's id", "missing", PACKAGE + "correlationId",
                    "the sealed package cannot be traced by its request id");
            return;
        }
        if (tally.subject().unreadSources().contains(PromptInspectionSources.REQUEST_FACTS)) {
            return;
        }
        String named = text(tally.subject().sources().requestFacts().get("requestId"));
        record(tally, correlationId.equals(named), "requestId", correlationId, hasText(named) ? named : "missing",
                PACKAGE + PromptInspectionSources.REQUEST_FACTS + ".requestId",
                "the request facts sealed with the package name another request");
    }

    private static void record(PromptInspectionTally tally, boolean kept, String entry, String expected, String actual,
                               String source, String reason) {
        if (kept) {
            tally.matched();
            return;
        }
        tally.mismatch(tally.mismatchFinding().entry(entry).expected(expected).actual(actual).sourceRef(source)
                .reason(reason).build());
    }

    /** The prompt hash form of the render metadata and the assembler: {@code sha256:} and the hex digest. */
    public static String sha256(String value) {
        return PromptGovernanceSupport.sha256(text(value));
    }

    private static String normalized(String value) {
        return value == null ? "" : value.replace("\r\n", "\n").replace('\r', '\n').stripTrailing();
    }

    private static String firstText(String... values) {
        for (String value : values) {
            if (hasText(value)) {
                return value;
            }
        }
        return null;
    }

    private static String text(Object value) {
        return value == null ? "" : value.toString();
    }

    private static boolean hasText(String value) {
        return value != null && !value.isBlank();
    }
}
