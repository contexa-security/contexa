package io.contexa.contexacore.verification.evidence;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.Objects;

/**
 * The OSS capture sample (R4-S6, decision D-B): a stable share of the requests is sealed, and every decision of a window
 * after a change. A window opens when the node starts, since the inspector and dictionary versions are build constants
 * that change only with a new start, and again whenever the active prompt bundle changes while the node runs.
 */
public class VersionChangeCaptureSampling implements SealedEvidenceCaptureSampling {

    public static final int DEFAULT_SAMPLE_PERCENT = 1;

    public static final int DEFAULT_FULL_CAPTURE_AFTER_CHANGE = 1000;

    private final int samplePercent;
    private final int fullCaptureAfterChange;
    private final ObjectMapper objectMapper;
    private boolean started;
    private String bundleVersion;
    private int windowLeft;

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
        String version = bundleVersion(evidencePackage);
        if (!started || !Objects.equals(version, bundleVersion)) {
            started = true;
            bundleVersion = version;
            windowLeft = fullCaptureAfterChange;
        }
        if (windowLeft > 0) {
            windowLeft--;
            return true;
        }
        return inSample(evidencePackage.getCorrelationId());
    }

    /** A stable hash of the request id, so that a request left out stays out. */
    private boolean inSample(String correlationId) {
        if (samplePercent >= 100) {
            return true;
        }
        return correlationId != null && Math.floorMod(correlationId.hashCode(), 100) < samplePercent;
    }

    private String bundleVersion(SealedEvidencePackage evidencePackage) {
        String metadata = evidencePackage.getPromptExecutionMetadataJson();
        if (metadata == null || metadata.isBlank()) {
            return null;
        }
        try {
            return objectMapper.readTree(metadata).path("governanceDescriptor").path("promptBundleVersion")
                    .asText(null);
        } catch (Exception exception) {
            // The version only keys the full-capture window; metadata that cannot be read counts as no version.
            return null;
        }
    }
}
