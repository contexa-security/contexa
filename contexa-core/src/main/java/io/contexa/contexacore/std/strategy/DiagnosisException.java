package io.contexa.contexacore.std.strategy;

/**
 * AI 진단 실행 중 발생하는 예외
 * 
 * 각 DiagnosisStrategy 구현체에서 진단 실행 중 오류 발생 시 던지는 예외
 */
public class DiagnosisException extends RuntimeException {
    
    private final String diagnosisType;
    private final String errorCode;
    
    public DiagnosisException(String message) {
        super(message);
        this.diagnosisType = null;
        this.errorCode = null;
    }
    
    public DiagnosisException(String message, Throwable cause) {
        super(message, cause);
        this.diagnosisType = null;
        this.errorCode = null;
    }
    
    public DiagnosisException(String diagnosisType, String errorCode, String message) {
        super(String.format("[%s:%s] %s", diagnosisType, errorCode, message));
        this.diagnosisType = diagnosisType;
        this.errorCode = errorCode;
    }
    
    public DiagnosisException(String diagnosisType, String errorCode, String message, Throwable cause) {
        super(String.format("[%s:%s] %s", diagnosisType, errorCode, message), cause);
        this.diagnosisType = diagnosisType;
        this.errorCode = errorCode;
    }
    
    public String getDiagnosisType() {
        return diagnosisType;
    }
    
    public String getErrorCode() {
        return errorCode;
    }
} 