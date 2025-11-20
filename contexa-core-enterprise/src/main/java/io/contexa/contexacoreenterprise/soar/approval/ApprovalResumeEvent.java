package io.contexa.contexacoreenterprise.soar.approval;

import io.contexa.contexacore.domain.SoarRequest;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Event published when an approval is completed and the pipeline needs to resume
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class ApprovalResumeEvent {
    private SoarRequest soarRequest;
    private String approvalId;
    private boolean approved;
    private String comment;
    private String reviewer;
}