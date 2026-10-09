package io.contexa.showcase.portal.spec;

import java.util.Map;
import java.util.Objects;

/**
 * Everything that determines a recorded or live result. Two results are comparable only when their
 * execution specs hash to the same value (rule documented in docs/showcase/실행명세.md).
 *
 * @param codeCommit          commit of the showcase and engine sources that produced the result
 * @param engineVersion       Contexa engine version
 * @param effectiveMode       Zero Trust mode in force at run time (database setting wins over properties)
 * @param endpointProtection  protected endpoint to "sync" or "async"
 * @param chatModel           chat model name and version
 * @param embeddingModel      embedding model name
 * @param embeddingDimensions embedding dimensions
 * @param promptHash          hash of the security decision prompt template
 * @param templateId          learned-state template the run principal was cloned from, if any
 * @param ruleVersion         hash of the frozen rule controls C1 and C2
 * @param contractVersion     hash of the frozen scoring contract, if any
 * @param timeZone            time zone of the virtual company
 * @param modelSettings       the model settings control D sends with every analysis, per layer (reasoning effort,
 *                            verbosity, output limit); null for specifications recorded before they were reported
 */
public record ExecutionSpec(
        String codeCommit,
        String engineVersion,
        String effectiveMode,
        Map<String, String> endpointProtection,
        String chatModel,
        String embeddingModel,
        int embeddingDimensions,
        String promptHash,
        String templateId,
        String ruleVersion,
        String contractVersion,
        String timeZone,
        Map<String, Object> modelSettings) {

    /**
     * The prompt hash of a run in which the engine made no model call (refused by the permission check or by an earlier
     * decision before any analysis): the run still has an execution specification (H-22), with no prompt in it.
     */
    public static final String NO_MODEL_CALL = "NO_MODEL_CALL";

    public ExecutionSpec {
        Objects.requireNonNull(codeCommit, "codeCommit");
        Objects.requireNonNull(engineVersion, "engineVersion");
        Objects.requireNonNull(effectiveMode, "effectiveMode");
        endpointProtection = Map.copyOf(Objects.requireNonNull(endpointProtection, "endpointProtection"));
        Objects.requireNonNull(chatModel, "chatModel");
        Objects.requireNonNull(embeddingModel, "embeddingModel");
        Objects.requireNonNull(promptHash, "promptHash");
        Objects.requireNonNull(ruleVersion, "ruleVersion");
        Objects.requireNonNull(timeZone, "timeZone");
        modelSettings = modelSettings == null || modelSettings.isEmpty() ? null : Map.copyOf(modelSettings);
        if (embeddingDimensions <= 0) {
            throw new IllegalArgumentException("embeddingDimensions must be positive");
        }
    }
}
