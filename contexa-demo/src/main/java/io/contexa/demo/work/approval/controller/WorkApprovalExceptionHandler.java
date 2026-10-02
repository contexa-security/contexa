package io.contexa.demo.work.approval.controller;

import io.contexa.demo.work.approval.dto.WorkApprovalFailure;
import io.contexa.demo.work.approval.service.WorkApprovalException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice(basePackages = "io.contexa.demo.work")
public class WorkApprovalExceptionHandler {

    @ExceptionHandler(WorkApprovalException.class)
    public ResponseEntity<WorkApprovalFailure> approval(WorkApprovalException failure) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(new WorkApprovalFailure("WORK_APPROVAL_UNUSABLE", failure.status()));
    }
}
