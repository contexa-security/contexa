package io.contexa.contexaiam.common;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.MediaType;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(Throwable.class)
    public ResponseEntity<?> handleGeneralException(Throwable ex, HttpServletRequest request) {

        log.error("Unhandled exception occurred: {}", ex.getMessage(), ex);

        String acceptHeader = request.getHeader("Accept");
        if (acceptHeader != null && acceptHeader.contains("text/event-stream")) {
            String sseError = "data: ERROR: An unexpected error occurred\n\n";
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .contentType(MediaType.TEXT_EVENT_STREAM)
                    .body(sseError);
        }

        ErrorResponse errorResponse = new ErrorResponse(
            LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME),
            HttpStatus.INTERNAL_SERVER_ERROR.value(),
            "GENERAL_ERROR",
            "An unexpected error occurred",
            null
        );
        return new ResponseEntity<>(errorResponse, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @ExceptionHandler(NoResourceFoundException.class)
    public ResponseEntity<ErrorResponse> handleNoResourceFoundException(NoResourceFoundException ex) {

        ErrorResponse errorResponse = new ErrorResponse(
            LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME),
            HttpStatus.NOT_FOUND.value(),
            "RESOURCE_NOT_FOUND",
            "Requested resource not found",
            null
        );
        return new ResponseEntity<>(errorResponse, HttpStatus.NOT_FOUND);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ErrorResponse> handleIllegalArgumentException(IllegalArgumentException ex) {

        ErrorResponse errorResponse = new ErrorResponse(
            LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME),
            HttpStatus.BAD_REQUEST.value(),
            "INVALID_ARGUMENT",
            ex.getMessage() != null ? ex.getMessage() : "Invalid request parameter",
            null
        );
        return new ResponseEntity<>(errorResponse, HttpStatus.BAD_REQUEST);
    }
}
