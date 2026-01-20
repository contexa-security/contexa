package io.contexa.contexacore.std.strategy;


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