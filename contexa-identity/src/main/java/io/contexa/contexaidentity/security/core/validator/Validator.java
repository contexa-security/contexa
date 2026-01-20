package io.contexa.contexaidentity.security.core.validator;


public interface Validator<T> {
    ValidationResult validate(T target);
}

