package io.contexa.contexacoreenterprise.soar.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class McpStatusResponse {
    private boolean context7;
    private boolean sequential;
    private boolean magic;
    private boolean playwright;
    private LocalDateTime timestamp;
}
