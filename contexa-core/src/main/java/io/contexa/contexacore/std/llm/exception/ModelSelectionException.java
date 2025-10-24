package io.contexa.contexacore.std.llm.exception;

/**
 * 모델 선택 실패 시 발생하는 예외
 */
public class ModelSelectionException extends RuntimeException {

    private final String modelName;
    private final Integer tier;

    public ModelSelectionException(String message) {
        super(message);
        this.modelName = null;
        this.tier = null;
    }

    public ModelSelectionException(String message, Throwable cause) {
        super(message, cause);
        this.modelName = null;
        this.tier = null;
    }

    public ModelSelectionException(String message, String modelName) {
        super(message);
        this.modelName = modelName;
        this.tier = null;
    }

    public ModelSelectionException(String message, Integer tier) {
        super(message);
        this.modelName = null;
        this.tier = tier;
    }

    public ModelSelectionException(String message, String modelName, Throwable cause) {
        super(message, cause);
        this.modelName = modelName;
        this.tier = null;
    }

    public String getModelName() {
        return modelName;
    }

    public Integer getTier() {
        return tier;
    }
}