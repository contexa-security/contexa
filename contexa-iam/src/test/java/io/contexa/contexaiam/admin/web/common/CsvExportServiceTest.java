/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexaiam.admin.web.common;

import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.WriteListener;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("CsvExportService")
class CsvExportServiceTest {

    @InjectMocks
    private CsvExportService csvExportService;

    @Mock
    private HttpServletResponse response;

    private ByteArrayOutputStream outputStream;

    @BeforeEach
    void setUp() throws IOException {
        outputStream = new ByteArrayOutputStream();
        ServletOutputStream servletOutputStream = new ServletOutputStream() {
            @Override
            public boolean isReady() {
                return true;
            }

            @Override
            public void setWriteListener(WriteListener writeListener) {
            }

            @Override
            public void write(int b) throws IOException {
                outputStream.write(b);
            }

            @Override
            public void write(byte[] b, int off, int len) throws IOException {
                outputStream.write(b, off, len);
            }
        };
        when(response.getOutputStream()).thenReturn(servletOutputStream);
    }

    @Test
    @DisplayName("export should stream valid csv structure with headers and UTF-8 BOM")
    void exportSuccess() throws IOException {
        List<CsvColumn<TestItem>> columns = List.of(
                new CsvColumn<>("Name", TestItem::name),
                new CsvColumn<>("Value", item -> String.valueOf(item.value()))
        );

        csvExportService.export(response, "test-prefix", columns, () -> Stream.of(
                new TestItem("Alice", 10),
                new TestItem("Bob", 20)
        ));

        verify(response).setContentType("text/csv; charset=UTF-8");
        verify(response).setHeader(eq("Content-Disposition"), startsWith("attachment; filename=\"test-prefix-"));
        verify(response).setCharacterEncoding("UTF-8");

        byte[] bytes = outputStream.toByteArray();
        // UTF-8 BOM check: EF, BB, BF
        assertThat(bytes[0]).isEqualTo((byte) 0xEF);
        assertThat(bytes[1]).isEqualTo((byte) 0xBB);
        assertThat(bytes[2]).isEqualTo((byte) 0xBF);

        String csvContent = new String(bytes, 3, bytes.length - 3, StandardCharsets.UTF_8);
        String[] lines = csvContent.split("\n");

        assertThat(lines).hasSize(3);
        assertThat(lines[0].trim()).isEqualTo("Name,Value");
        assertThat(lines[1].trim()).isEqualTo("Alice,10");
        assertThat(lines[2].trim()).isEqualTo("Bob,20");
    }

    @Test
    @DisplayName("export should escape csv special characters properly")
    void exportWithEscaping() throws IOException {
        List<CsvColumn<TestItem>> columns = List.of(
                new CsvColumn<>("Field,1", TestItem::name)
        );

        csvExportService.export(response, "escape-prefix", columns, () -> Stream.of(
                new TestItem("Hello, \"World\"", 1),
                new TestItem("Line\nBreak", 2),
                new TestItem(null, 3)
        ));

        byte[] bytes = outputStream.toByteArray();
        String csvContent = new String(bytes, 3, bytes.length - 3, StandardCharsets.UTF_8);
        String[] lines = csvContent.split("\n", -1);

        // Header: "Field,1" because it contains a comma
        assertThat(lines[0].trim()).isEqualTo("\"Field,1\"");
        // Row 1: "Hello, \"World\"" -> contains comma & quotes -> escape to "Hello, ""World""" and surround with quotes -> "\"Hello, \"\"World\"\"\""
        assertThat(lines[1].trim()).isEqualTo("\"Hello, \"\"World\"\"\"");
        // Row 2: "Line\nBreak" -> contains newline. Since we split by \n, this splits across two lines.
        assertThat(lines[2].trim()).isEqualTo("\"Line");
        assertThat(lines[3].trim()).isEqualTo("Break\"");
        // Row 3: null -> empty string
        assertThat(lines[4].trim()).isEqualTo("");
    }

    @Test
    @DisplayName("export should propagate IOException if output stream fails")
    void exportIoException() throws IOException {
        when(response.getOutputStream()).thenThrow(new IOException("Stream closed"));

        List<CsvColumn<TestItem>> columns = List.of(new CsvColumn<>("Header", TestItem::name));

        assertThrows(IOException.class, () ->
                csvExportService.export(response, "error", columns, Stream::empty)
        );
    }

    record TestItem(String name, int value) {}
}
