package io.contexa.demo.shared.web;

import io.contexa.demo.shared.web.dto.ApiFailure;
import org.springframework.dao.DataAccessException;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.server.ResponseStatusException;

@RestControllerAdvice(basePackages = "io.contexa.demo")
public class LabExceptionHandler {

    @ExceptionHandler(ResponseStatusException.class)
    ResponseEntity<ApiFailure> rejected(ResponseStatusException failure) {
        String reason = failure.getReason();
        String state = reason != null && reason.matches("[A-Z][A-Z0-9_]{1,80}") ? reason : "REQUEST_REJECTED";
        return ResponseEntity.status(failure.getStatusCode())
                .body(new ApiFailure(state, "현재 상태를 확인해 주세요."));
    }

    @ExceptionHandler({MethodArgumentNotValidException.class, HttpMessageNotReadableException.class})
    ResponseEntity<ApiFailure> invalid(Exception failure) {
        return ResponseEntity.badRequest().body(new ApiFailure("INVALID_INPUT", "입력 내용을 확인해 주세요."));
    }

    @ExceptionHandler(DataAccessException.class)
    ResponseEntity<ApiFailure> unavailable(DataAccessException failure) {
        return ResponseEntity.status(503).body(new ApiFailure("STORE_UNAVAILABLE", "잠시 후 다시 시도해 주세요."));
    }
}
