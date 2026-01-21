package io.contexa.contexaidentity.security.core.validator;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class ValidationResult {
    private final List<String> errors;
    private final List<String> warnings; 

    public ValidationResult() {
        this.errors = new ArrayList<>();
        this.warnings = new ArrayList<>();
    }

    public void addError(String msg) {
        errors.add(msg);
    }

    public void addWarning(String msg) { 
        warnings.add(msg);
    }

    public boolean hasErrors() { 
        return !errors.isEmpty();
    }

    public boolean hasWarnings() {
        return !warnings.isEmpty();
    }

    public boolean isValid() { 
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

