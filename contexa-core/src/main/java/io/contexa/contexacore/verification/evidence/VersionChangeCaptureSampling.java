package io.contexa.contexacore.verification.evidence;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.std.components.prompt.PromptExecutionMetadata;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * The OSS capture sample (R4-S6, decision D-B): a stable share of the requests is sealed, and every decision of a window
 * after a change. A window opens when the node starts, since the inspector and dictionary versions are build constants
 * that change only with a new start, and again whenever the version decisions run changes while the node runs: the
 * label moved, a rollback, the setting (K43). The version is the name and content hash fixed on the decision (plan 3.8
 * (9)), not the bundle every version shares; a package that records only its bundle (an earlier build's) is keyed by
 * the bundle. A version a canary's share or a shadow runs beside it has a window of its own, opened the first time the
 * node seals one of its decisions, so the turns of the share do not open the window of the version in use again.
 */
public class VersionChangeCaptureSampling implements SealedEvidenceCaptureSampling {

    public static final int DEFAULT_SAMPLE_PERCENT = 1;

    public static final int DEFAULT_FULL_CAPTURE_AFTER_CHANGE = 1000;

    /** The versions whose windows this node keeps, at most so many (the least recently sealed one goes first). */
    static final int KEPT_VERSIONS = 256;
    /** The sources of a version that runs beside the version in use: they do not change the version in use. */
    private static final Set<String> BESIDE_IN_USE = Set.of("CANARY", "SHADOW", "REPLAY");
    private static final String SELECTION_SOURCE = "promptBundleSelectionSource";

    private final int samplePercent;
    private final int fullCaptureAfterChange;
    private final ObjectMapper objectMapper;
    private boolean started;
    private String inUse;

    /** The decisions each version's window still seals in full, by version. */
    private final Map<String, Integer> windowLeft = new LinkedHashMap<>(16, 0.75f, true) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, Integer> eldest) {
            return size() > KEPT_VERSIONS;
        }
    };

    public VersionChangeCaptureSampling(int samplePercent, int fullCaptureAfterChange, ObjectMapper objectMapper) {
        if (samplePercent < 1 || samplePercent > 100) {
            throw new IllegalArgumentException("samplePercent must be between 1 and 100");
        }
        if (fullCaptureAfterChange < 0) {
            throw new IllegalArgumentException("fullCaptureAfterChange must not be negative");
        }
        this.samplePercent = samplePercent;
        this.fullCaptureAfterChange = fullCaptureAfterChange;
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper");
    }

    @Override
    public synchronized boolean shouldSeal(SealedEvidencePackage evidencePackage) {
        JsonNode metadata = metadataOf(evidencePackage);
        String version = versionOf(metadata);
        String source = metadata != null ? text(metadata.path(SELECTION_SOURCE)) : null;
        boolean besideInUse = source != null && BESIDE_IN_USE.contains(source);
        if (!besideInUse && (!started || !Objects.equals(version, inUse))) {
            started = true;
            inUse = version;
            windowLeft.put(version, fullCaptureAfterChange);
        }
        Integer left = windowLeft.get(version);
        int remaining = left != null ? left : fullCaptureAfterChange;
        if (remaining > 0) {
            windowLeft.put(version, remaining - 1);
            return true;
        }
        windowLeft.put(version, 0);
        return inSample(evidencePackage.getCorrelationId());
    }

    /** A stable hash of the request id, so that a request left out stays out. */
    private boolean inSample(String correlationId) {
        if (samplePercent >= 100) {
            return true;
        }
        return correlationId != null && Math.floorMod(correlationId.hashCode(), 100) < samplePercent;
    }

    private JsonNode metadataOf(SealedEvidencePackage evidencePackage) {
        String metadata = evidencePackage.getPromptExecutionMetadataJson();
        if (metadata == null || metadata.isBlank()) {
            return null;
        }
        try {
            return objectMapper.readTree(metadata);
        } catch (Exception exception) {
            // The version only keys the full-capture window; metadata that cannot be read counts as no version.
            return null;
        }
    }

    /**
     * The version the decision ran, with its content hash ({@code v2.0@hash}), as the package records it; the bundle of
     * a package that records no version name; null when the metadata says neither.
     */
    private static String versionOf(JsonNode metadata) {
        if (metadata == null) {
            return null;
        }
        String name = text(metadata.path(PromptExecutionMetadata.PROMPT_VERSION_NAME));
        if (name != null) {
            String hash = text(metadata.path(PromptExecutionMetadata.PROMPT_CONTENT_HASH));
            return hash != null ? name + "@" + hash : name;
        }
        return text(metadata.path(PromptExecutionMetadata.GOVERNANCE_DESCRIPTOR).path("promptBundleVersion"));
    }

    private static String text(JsonNode node) {
        String value = node.isValueNode() ? node.asText(null) : null;
        return value != null && !value.isBlank() ? value.trim() : null;
    }
}
