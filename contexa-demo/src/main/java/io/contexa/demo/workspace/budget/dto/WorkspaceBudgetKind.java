package io.contexa.demo.workspace.budget.dto;

public enum WorkspaceBudgetKind {
    COMPARISON("comparison"), CHAT("chat"), EMBEDDING("embedding"), WORK("work");

    private final String column;

    WorkspaceBudgetKind(String column) {
        this.column = column;
    }

    public String column() {
        return column;
    }
}
