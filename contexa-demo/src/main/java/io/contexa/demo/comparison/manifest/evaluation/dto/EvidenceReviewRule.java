package io.contexa.demo.comparison.manifest.evaluation.dto;

import java.util.List;

public record EvidenceReviewRule(String id, List<String> requiredSources, String reviewBoundary) {
}
