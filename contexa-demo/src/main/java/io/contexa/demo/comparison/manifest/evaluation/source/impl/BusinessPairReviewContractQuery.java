package io.contexa.demo.comparison.manifest.evaluation.source.impl;

import io.contexa.demo.comparison.manifest.evaluation.dto.EvidenceReviewRule;
import io.contexa.demo.comparison.manifest.evaluation.dto.FrozenReviewContract;
import io.contexa.demo.comparison.manifest.evaluation.source.ReviewContractQuery;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import java.util.List;
import java.util.Set;

@Component
@Profile("portal")
public class BusinessPairReviewContractQuery implements ReviewContractQuery {

    @Override
    public FrozenReviewContract capture(String planKind) {
        if (!Set.of("DOCUMENT_READ_PAIR", "CUSTOMER_READ_PAIR", "DOCUMENT_DOWNLOAD_PAIR", "BUSINESS_EXPORT_PAIR").contains(planKind)) {
            throw new IllegalArgumentException("Unsupported review contract plan");
        }
        boolean customer = "CUSTOMER_READ_PAIR".equals(planKind);
        boolean batch = "BUSINESS_EXPORT_PAIR".equals(planKind);
        boolean download = "DOCUMENT_DOWNLOAD_PAIR".equals(planKind) || batch;
        String version = batch ? "BUSINESS_EXPORT_PAIR_SOURCE_REVIEW_V1" : download ? "DOCUMENT_FILE_PAIR_SOURCE_REVIEW_V1"
                : customer ? "CUSTOMER_PAIR_SOURCE_REVIEW_V1" : "DOCUMENT_PAIR_SOURCE_REVIEW_V1";
        return new FrozenReviewContract(version, planKind, List.of(
                new EvidenceReviewRule("INITIAL_CONDITIONS", List.of("PREPARATION", "BOTH_ARM_ATTESTATIONS"),
                        batch ? "SAME_TARGETS_VERSIONS_APPROVAL_STATUS_PURPOSE_AND_SCOPE_WITH_OWN_APPROVAL_REFERENCES"
                                : customer ? "SAME_ACCOUNT_PERMISSIONS_AUTHENTICATION_CUSTOMER_AND_APPLICATION_BEFORE_DISPATCH"
                                : "SAME_ACCOUNT_PERMISSIONS_AUTHENTICATION_DOCUMENT_AND_APPLICATION_BEFORE_DISPATCH"),
                new EvidenceReviewRule("BUSINESS_DELIVERY", List.of("DISPATCH", "HTTP", "BUSINESS_SNAPSHOT",
                        download ? "FILE_EFFECT" : "READ_EFFECT", "CLIENT_RECEIPT"),
                        "KEEP_REQUESTED_PROCESSED_TRANSMITTED_AND_RECEIVED_FACTS_SEPARATE"),
                new EvidenceReviewRule("NATIVE_CONTROL", List.of("MODEL_BOUNDARY", "PROVIDER_BOUNDARY", "FINAL_DECISION", "ACTION_APPLICATION"),
                        "DISTINGUISH_NEW_ANALYSIS_EXISTING_ACTION_TECHNICAL_FAILURE_AND_ACTUAL_ENFORCEMENT"),
                new EvidenceReviewRule("NATIVE_LEARNING", List.of("LEARNING_CALL", "BASELINE_WRITE", "RAG_WRITE", "SEARCH_TRACE"),
                        "NO_LEARNING_OR_SEARCH_INFERRED_FROM_HTTP_STATUS_OR_TOTAL_REQUEST_COUNT")),
                "INSUFFICIENT_EVIDENCE_NOT_ZERO_OR_SUCCESS", "NOT_ASSESSED_BY_THIS_EXECUTION_CONTRACT", false);
    }
}
