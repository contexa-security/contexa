package io.contexa.contexacore.verification.replay;

import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.prompt.PromptContextComposer;
import io.contexa.contexacore.verification.evidence.CanonicalSecurityContextSerializer;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageIntegrity;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageLookupPort;
import io.contexa.contexacore.verification.prompt.VerificationPromptReplayBuilder;
import io.contexa.contexacore.verification.prompt.VerificationPromptReplayContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Deterministic Replay verifies that:
 * 1. The sealed evidence package has not been tampered with (integrity hash)
 * 2. The CanonicalSecurityContext can be faithfully restored from sealed JSON
 * 3. PromptContextComposer produces the same context sections from the restored context
 * 4. The sealed prompt originals (raw + LLM-view) are internally consistent
 * 5. All essential sections are present and non-empty
 * 6. Byte-level diff between reassembled and original prompts
 *
 * This service is strictly read-only: it never modifies production state.
 */
@Slf4j
@RequiredArgsConstructor
public class DeterministicReplayService {

    private final SealedEvidencePackageLookupPort lookupService;
    private final CanonicalSecurityContextSerializer contextSerializer;
    private final PromptContextComposer promptContextComposer;
    private final SealedEvidencePackageIntegrity integrity;
    private final VerificationPromptReplayBuilder promptReplayBuilder;

    public DeterministicReplayResult replay(String packageId) {
        SealedEvidencePackage pkg = lookupService.findByPackageId(packageId)
                .orElseThrow(() -> new IllegalArgumentException(
                        "Sealed evidence package not found: " + packageId));

        List<String> findings = new ArrayList<>();
        List<DiffSection> systemPromptDiff = new ArrayList<>();
        List<DiffSection> userPromptDiff = new ArrayList<>();
        int checksRun = 0;
        int checksPassed = 0;

        checksRun++;
        if (integrity.verify(pkg)) {
            checksPassed++;
        } else {
            findings.add("INTEGRITY_FAILED: packageHash mismatch -- evidence may have been tampered");
        }

        checksRun++;
        CanonicalSecurityContext context = contextSerializer.deserialize(pkg.getCanonicalContextJson());
        if (context != null) {
            checksPassed++;
        } else {
            findings.add("CANONICAL_CONTEXT_MISSING: cannot deserialize CanonicalSecurityContext from sealed JSON");
            return buildResult(pkg, checksRun, checksPassed, findings, systemPromptDiff, userPromptDiff, null);
        }

        checksRun++;
        String reassembledContextSections = promptContextComposer.compose(context);
        VerificationPromptReplayContext replayContext =
                promptReplayBuilder.buildDeterministicReplayContext(pkg, reassembledContextSections);
        if (reassembledContextSections != null && !reassembledContextSections.isBlank()) {
            checksPassed++;
        } else {
            findings.add("CONTEXT_REASSEMBLY_EMPTY: PromptContextComposer.compose() returned null or blank");
        }

        String rawUserPrompt = replayContext.rawUserPrompt();
        String systemPromptText = replayContext.systemPrompt();
        String userPromptText = replayContext.userPrompt();

        checksRun++;
        if (selectedCanonicalSectionsMatch(rawUserPrompt, reassembledContextSections)) {
            checksPassed++;
        } else if (rawUserPrompt == null) {
            findings.add("RAW_USER_PROMPT_MISSING: sealed evidence lacks raw user prompt");
        } else {
            findings.add("CONTEXT_SECTION_DRIFT: reassembled context sections not found verbatim in sealed raw user prompt");
            if (reassembledContextSections != null) {
                userPromptDiff.addAll(computeLineDiff(rawUserPrompt, reassembledContextSections));
            }
        }

        checksRun++;
        if (systemPromptText != null && !systemPromptText.isBlank()) {
            checksPassed++;
        } else {
            findings.add("LLM_SYSTEM_PROMPT_MISSING: sealed evidence lacks LLM-view system prompt");
        }

        checksRun++;
        if (userPromptText != null && !userPromptText.isBlank()) {
            checksPassed++;
        } else {
            findings.add("LLM_USER_PROMPT_MISSING: sealed evidence lacks LLM-view user prompt");
        }

        checksRun++;
        if (rawUserPrompt != null && userPromptText != null) {
            if (userPromptText.length() <= rawUserPrompt.length()) {
                checksPassed++;
            } else {
                findings.add("PROMPT_COMPRESSION_ANOMALY: LLM-view user prompt is longer than raw");
            }
        } else {
            findings.add("PROMPT_COMPARISON_SKIPPED: raw or LLM-view user prompt missing");
        }

        checksRun++;
        String rawSystemPrompt = replayContext.rawSystemPrompt();
        if (rawSystemPrompt != null && systemPromptText != null) {
            if (rawSystemPrompt.equals(systemPromptText)) {
                checksPassed++;
            } else {
                findings.add("SYSTEM_PROMPT_COMPRESSION_APPLIED: raw and LLM-view system prompts differ");
                systemPromptDiff.addAll(computeLineDiff(rawSystemPrompt, systemPromptText));
            }
        } else {
            findings.add("SYSTEM_PROMPT_COMPARISON_SKIPPED: raw or LLM-view system prompt missing");
        }

        checksRun++;
        if (pkg.getPromptHash() != null && !pkg.getPromptHash().isBlank()) {
            checksPassed++;
        } else {
            findings.add("PROMPT_HASH_MISSING: sealed evidence lacks prompt hash");
        }

        checksRun++;
        if (pkg.getPromptExecutionMetadataJson() != null && !pkg.getPromptExecutionMetadataJson().isBlank()) {
            checksPassed++;
        } else {
            findings.add("PROMPT_EXECUTION_METADATA_MISSING: sealed evidence lacks prompt execution metadata");
        }

        checksRun++;
        if (pkg.getDecisionJson() != null && !pkg.getDecisionJson().isBlank()) {
            checksPassed++;
        } else {
            findings.add("DECISION_MISSING: sealed evidence lacks decision snapshot");
        }

        checksRun++;
        if (pkg.getRequestFactsJson() != null && !pkg.getRequestFactsJson().isBlank()) {
            checksPassed++;
        } else {
            findings.add("REQUEST_FACTS_MISSING: sealed evidence lacks request facts");
        }

        checksRun++;
        if (pkg.getAuthStateJson() != null && !pkg.getAuthStateJson().isBlank()) {
            checksPassed++;
        } else {
            findings.add("AUTH_STATE_MISSING: sealed evidence lacks authentication state");
        }

        String reconstructedHash = null;
        return buildResult(pkg, checksRun, checksPassed, findings, systemPromptDiff, userPromptDiff, reconstructedHash);
    }

    private boolean selectedCanonicalSectionsMatch(String rawUserPrompt, String reassembledContextSections) {
        if (rawUserPrompt == null || rawUserPrompt.isBlank()
                || reassembledContextSections == null || reassembledContextSections.isBlank()) {
            return false;
        }
        List<String> sections = Arrays.stream(reassembledContextSections.split("(?m)(?=^=== )"))
                .map(String::strip)
                .filter(section -> !section.isBlank())
                .toList();
        int selectedSections = 0;
        int exactMatches = 0;
        for (String section : sections) {
            String header = section.lines().findFirst().orElse("");
            if (header.isBlank() || !rawUserPrompt.contains(header)) {
                continue;
            }
            selectedSections++;
            if (rawUserPrompt.contains(section)) {
                exactMatches++;
            }
        }
        return selectedSections > 0 && selectedSections == exactMatches;
    }

    private List<DiffSection> computeLineDiff(String original, String reconstructed) {
        List<DiffSection> diffs = new ArrayList<>();
        if (original == null || reconstructed == null) {
            return diffs;
        }

        String[] origLines = original.split("\n", -1);
        String[] reconLines = reconstructed.split("\n", -1);
        int maxLines = Math.max(origLines.length, reconLines.length);

        for (int i = 0; i < maxLines; i++) {
            String origLine = i < origLines.length ? origLines[i] : null;
            String reconLine = i < reconLines.length ? reconLines[i] : null;

            if (origLine == null && reconLine != null) {
                diffs.add(new DiffSection(i + 1, DiffSection.ADDED, null, reconLine));
            } else if (origLine != null && reconLine == null) {
                diffs.add(new DiffSection(i + 1, DiffSection.REMOVED, origLine, null));
            } else if (origLine != null && !origLine.equals(reconLine)) {
                diffs.add(new DiffSection(i + 1, DiffSection.CHANGED, origLine, reconLine));
            }
        }
        return diffs;
    }

    private DeterministicReplayResult buildResult(SealedEvidencePackage pkg,
                                                   int checksRun, int checksPassed,
                                                   List<String> findings,
                                                   List<DiffSection> systemPromptDiff,
                                                   List<DiffSection> userPromptDiff,
                                                   String reconstructedHash) {
        return new DeterministicReplayResult(
                pkg.getPackageId(),
                checksRun == checksPassed,
                pkg.getPromptHash(),
                reconstructedHash,
                checksRun,
                checksPassed,
                List.copyOf(findings),
                List.copyOf(systemPromptDiff),
                List.copyOf(userPromptDiff),
                Instant.now()
        );
    }
}
