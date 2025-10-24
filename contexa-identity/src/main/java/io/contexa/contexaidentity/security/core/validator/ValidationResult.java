package io.contexa.contexaidentity.security.core.validator;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class ValidationResult {
    private final List<String> errors;
    private final List<String> warnings; // 경고 메시지 추가

    public ValidationResult() {
        this.errors = new ArrayList<>();
        this.warnings = new ArrayList<>();
    }

    public void addError(String msg) {
        errors.add(msg);
    }

    public void addWarning(String msg) { // 경고 추가 메서드
        warnings.add(msg);
    }

    public boolean hasErrors() { // 실제 오류가 있는지 확인
        return !errors.isEmpty();
    }

    public boolean hasWarnings() {
        return !warnings.isEmpty();
    }

    public boolean isValid() { // 오류가 없을 때만 유효
        return errors.isEmpty();
    }

    public List<String> getErrors() {
        return Collections.unmodifiableList(errors);
    }

    public List<String> getWarnings() {
        return Collections.unmodifiableList(warnings);
    }

    public void merge(ValidationResult other) {
        if (other != null) {
            other.getErrors().forEach(this::addError);
            other.getWarnings().forEach(this::addWarning);
        }
    }
}


