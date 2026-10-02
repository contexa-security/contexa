package io.contexa.demo.work.export.dto;

import io.contexa.demo.work.shared.dto.BusinessResourceFacts;
import io.contexa.demo.work.shared.dto.WorkText;

public record ExportTarget(BusinessResourceFacts resource, WorkText label) {
}
