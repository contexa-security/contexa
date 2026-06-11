/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
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