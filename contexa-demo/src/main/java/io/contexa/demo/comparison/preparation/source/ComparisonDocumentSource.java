package io.contexa.demo.comparison.preparation.source;

import io.contexa.demo.comparison.preparation.dto.ArmDocumentFingerprint;

public interface ComparisonDocumentSource {

    ArmDocumentFingerprint capture(String documentId);
}
