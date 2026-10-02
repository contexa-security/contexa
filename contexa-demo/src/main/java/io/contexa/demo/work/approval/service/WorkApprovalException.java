package io.contexa.demo.work.approval.service;

public class WorkApprovalException extends RuntimeException {

    private final String status;

    public WorkApprovalException(String status) {
        super("WORK_APPROVAL_" + status);
        this.status = status;
    }

    public String status() {
        return status;
    }
}
