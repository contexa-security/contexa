package io.contexa.contexaiam.admin.web.common;

import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.function.Supplier;
import java.util.stream.Stream;

/**
 * Reusable CSV export service.
 * Supports any entity type via generic CsvColumn definitions.
 * Streams data to prevent memory issues with large datasets.
 */
@Slf4j
public class CsvExportService {

    private static final byte[] UTF8_BOM = {(byte) 0xEF, (byte) 0xBB, (byte) 0xBF};
    private static final DateTimeFormatter FILENAME_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd_HHmmss");

    /**
     * Export data as CSV with streaming response.
     *
     * @param response   HTTP response to write to
     * @param filePrefix filename prefix (e.g., "audit-log")
     * @param columns    column definitions with headers and extractors
     * @param dataSupplier supplies the data stream
     */
    public <T> void export(HttpServletResponse response,
                           String filePrefix,
                           List<CsvColumn<T>> columns,
                           Supplier<Stream<T>> dataSupplier) throws IOException {

        String filename = filePrefix + "-" + LocalDateTime.now().format(FILENAME_FORMATTER) + ".csv";

        response.setContentType("text/csv; charset=UTF-8");
        response.setHeader("Content-Disposition", "attachment; filename=\"" + filename + "\"");
        response.setCharacterEncoding("UTF-8");

        OutputStream outputStream = response.getOutputStream();
        outputStream.write(UTF8_BOM);

        try (Writer writer = new OutputStreamWriter(outputStream, StandardCharsets.UTF_8);
             Stream<T> data = dataSupplier.get()) {

            // Write header row
            StringBuilder headerLine = new StringBuilder();
            for (int i = 0; i < columns.size(); i++) {
                if (i > 0) headerLine.append(',');
                headerLine.append(escapeCsv(columns.get(i).header()));
            }
            writer.write(headerLine.toString());
            writer.write('\n');

            // Write data rows
            data.forEach(item -> {
                try {
                    StringBuilder row = new StringBuilder();
                    for (int i = 0; i < columns.size(); i++) {
                        if (i > 0) row.append(',');
                        String value = columns.get(i).extractor().apply(item);
                        row.append(escapeCsv(value));
                    }
                    writer.write(row.toString());
                    writer.write('\n');
                } catch (IOException e) {
                    log.error("CSV write error", e);
                }
            });

            writer.flush();
        }
    }

    private String escapeCsv(String value) {
        if (value == null) return "";
        if (value.contains(",") || value.contains("\"") || value.contains("\n") || value.contains("\r")) {
            return "\"" + value.replace("\"", "\"\"") + "\"";
        }
        return value;
    }
}
