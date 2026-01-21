package io.contexa.contexacore.std.llm.exception;

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