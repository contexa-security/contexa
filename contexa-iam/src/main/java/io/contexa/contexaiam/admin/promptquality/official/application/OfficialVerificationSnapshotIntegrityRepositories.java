package io.contexa.contexaiam.admin.promptquality.official.application;

import java.util.Objects;

public final class OfficialVerificationSnapshotIntegrityRepositories {
    private final OfficialVerificationSnapshotCompletionRepository completion;
    private final OfficialVerificationSnapshotRelationIntegrityRepository relation;
    private final OfficialVerificationCustomerPurposeIntegrityRepository customerPurpose;
    private final OfficialVerificationCustomerDisplayIntegrityRepository customerDisplay;
    private final OfficialVerificationContractLinkIntegrityRepository contractLink;

    public OfficialVerificationSnapshotIntegrityRepositories(
            OfficialVerificationSnapshotCompletionRepository completion,
            OfficialVerificationSnapshotRelationIntegrityRepository relation,
            OfficialVerificationCustomerPurposeIntegrityRepository customerPurpose,
            OfficialVerificationCustomerDisplayIntegrityRepository customerDisplay,
            OfficialVerificationContractLinkIntegrityRepository contractLink) {
        this.completion = Objects.requireNonNull(completion, "completion");
        this.relation = Objects.requireNonNull(relation, "relation");
        this.customerPurpose = Objects.requireNonNull(customerPurpose, "customerPurpose");
        this.customerDisplay = Objects.requireNonNull(customerDisplay, "customerDisplay");
        this.contractLink = Objects.requireNonNull(contractLink, "contractLink");
    }

    public OfficialVerificationSnapshotCompletionRepository completion() { return completion; }
    public OfficialVerificationSnapshotRelationIntegrityRepository relation() { return relation; }
    public OfficialVerificationCustomerPurposeIntegrityRepository customerPurpose() { return customerPurpose; }
    public OfficialVerificationCustomerDisplayIntegrityRepository customerDisplay() { return customerDisplay; }
    public OfficialVerificationContractLinkIntegrityRepository contractLink() { return contractLink; }
}