package io.contexa.demo.comparison.run.controller;

import io.contexa.demo.shared.web.dto.ApiFailure;
import io.contexa.demo.comparison.support.AbstractRunFailureSupport;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.server.ResponseStatusException;

@Profile("portal")
@RestControllerAdvice(assignableTypes = ComparisonRunController.class)
public class ComparisonRunExceptionHandler extends AbstractRunFailureSupport {

    @ExceptionHandler(ResponseStatusException.class)
    ResponseEntity<ApiFailure> rejected(ResponseStatusException failure) {
        return ResponseEntity.status(failure.getStatusCode())
                .body(new ApiFailure(publicReason(failure.getReason()), "실행 준비 상태를 확인해 주세요."));
    }
}
