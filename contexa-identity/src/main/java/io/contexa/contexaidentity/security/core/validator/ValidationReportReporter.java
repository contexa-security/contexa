package io.contexa.contexaidentity.security.core.validator;

import io.contexa.contexaidentity.security.exception.DslConfigurationException;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class ValidationReportReporter {

    private static final String BORDER_LINE = "=========================================================================================";
    private static final String ERROR_TITLE = "[ !!! DSL Security Configuration Validation Error !!! ]";
    private static final String WARNING_TITLE = "[ !!! DSL Security Configuration Validation Warning !!! ]";

    private static final String ERROR_PREFIX = "  [ERROR] ";
    private static final String WARNING_PREFIX = "  [WARNING] ";

    public static void reportAndThrowOnError(ValidationResult result, String dslSourceName) throws DslConfigurationException {
        if (result == null) {
            log.error("ValidationResult is null. Cannot report validation status for DSL source: {}", dslSourceName);
            throw new DslConfigurationException("Internal error during DSL validation: ValidationResult is null.");
        }

        boolean hasErrors = result.hasErrors();
        boolean hasWarnings = result.hasWarnings();

        if (!hasErrors && !hasWarnings) {
            return;
        }

        StringBuilder reportBuilder = new StringBuilder("\n\n");
        reportBuilder.append(BORDER_LINE).append("\n");

        if (hasErrors) {
            reportBuilder.append(String.format("%s (Config file: %s)\n", ERROR_TITLE, dslSourceName));
            reportBuilder.append("-----------------------------------------------------------------------------------------\n");
            reportBuilder.append("  The following configuration errors were found:\n");
            reportBuilder.append(BORDER_LINE).append("\n\n");
            for (int i = 0; i < result.getErrors().size(); i++) {
                reportBuilder.append(ERROR_PREFIX).append(i + 1).append(". ").append(result.getErrors().get(i)).append("\n");
            }
        } else {
            reportBuilder.append(String.format("%s (Config file: %s)\n", WARNING_TITLE, dslSourceName));
            reportBuilder.append("-----------------------------------------------------------------------------------------\n");
            reportBuilder.append("  The following configuration warnings were found:\n\n");
            for (int i = 0; i < result.getWarnings().size(); i++) {
                reportBuilder.append(WARNING_PREFIX).append(i + 1).append(". ").append(result.getWarnings().get(i)).append("\n");
            }
        }

        reportBuilder.append(BORDER_LINE).append("\n");

        if (hasErrors) {
            log.error(reportBuilder.toString());
            throw new DslConfigurationException("DSL configuration validation failed. Check logs for details. (Source: " + dslSourceName + ")");
        } else {
            log.error(reportBuilder.toString());
        }
    }
}
