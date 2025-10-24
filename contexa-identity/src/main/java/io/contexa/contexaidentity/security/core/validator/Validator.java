package io.contexa.contexaidentity.security.core.validator;

/**
 * 제네릭 Validator 인터페이스
 */
public interface Validator<T> {
    ValidationResult validate(T target);
}

