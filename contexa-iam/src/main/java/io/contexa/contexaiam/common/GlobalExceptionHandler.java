package io.contexa.contexaiam.common;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.MediaType;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(Throwable.class)
    public ResponseEntity<?> handleGeneralException(Throwable ex, HttpServletRequest request) {
        
        // SSE 요청인지 확인
        String acceptHeader = request.getHeader("Accept");
        if (acceptHeader != null && acceptHeader.contains("text/event-stream")) {
            // SSE 형태로 오류 응답
            String sseError = "data: ERROR: " + (ex.getMessage() != null ? ex.getMessage() : "An error occurred") + "\n\n";
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .contentType(MediaType.TEXT_EVENT_STREAM)
                    .body(sseError);
        }
        // 안전한 ErrorResponse 객체 생성 (JSON 직렬화 가능)
        ErrorResponse errorResponse = new ErrorResponse(
            LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME),
            HttpStatus.BAD_REQUEST.value(),
            "GENERAL_ERROR",
            ex.getMessage() != null ? ex.getMessage() : "An error occurred",
            null // path는 필요시 HttpServletRequest에서 가져올 수 있음
        );
        return new ResponseEntity<>(errorResponse, HttpStatus.BAD_REQUEST);
    }
    
    @ExceptionHandler(NoResourceFoundException.class)
    public ResponseEntity<ErrorResponse> handleNoResourceFoundException(NoResourceFoundException ex) {
        // 404 오류 전용 처리 (HttpMethod 직렬화 문제 방지)
        ErrorResponse errorResponse = new ErrorResponse(
            LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME),
            HttpStatus.NOT_FOUND.value(),
            "RESOURCE_NOT_FOUND",
            "요청한 리소스를 찾을 수 없습니다: " + ex.getResourcePath(),
            ex.getResourcePath()
        );
        return new ResponseEntity<>(errorResponse, HttpStatus.NOT_FOUND);
    }
    
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ErrorResponse> handleIllegalArgumentException(IllegalArgumentException ex) {
        // IllegalArgumentException 전용 처리
        ErrorResponse errorResponse = new ErrorResponse(
            LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME),
            HttpStatus.BAD_REQUEST.value(),
            "INVALID_ARGUMENT",
            ex.getMessage() != null ? ex.getMessage() : "잘못된 요청 매개변수입니다",
            null
        );
        return new ResponseEntity<>(errorResponse, HttpStatus.BAD_REQUEST);
    }
}
