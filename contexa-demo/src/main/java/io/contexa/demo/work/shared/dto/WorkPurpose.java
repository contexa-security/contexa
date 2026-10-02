package io.contexa.demo.work.shared.dto;

public enum WorkPurpose {
    PROJECT_REVIEW,
    CUSTOMER_SUPPORT,
    CROSS_PROJECT_REVIEW,
    APPROVED_BULK_DELIVERY,
    EMERGENCY_MAINTENANCE,
    UNDECLARED;

    public String source() {
        return this == UNDECLARED ? "NOT_PROVIDED" : "USER_DECLARATION";
    }
}
