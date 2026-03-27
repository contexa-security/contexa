package io.contexa.contexaiam.admin.web.common;

import java.util.function.Function;

/**
 * Defines a single column for CSV export.
 * Generic type T represents the source entity.
 */
public record CsvColumn<T>(String header, Function<T, String> extractor) {
}
