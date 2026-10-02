package io.contexa.demo.experience.report.render;

import io.contexa.demo.experience.report.dto.StoredReport;

public interface ReportRenderer {

    String html(StoredReport report, String language);
}
