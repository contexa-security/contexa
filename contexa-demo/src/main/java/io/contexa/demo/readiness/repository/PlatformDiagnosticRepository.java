package io.contexa.demo.readiness.repository;

import java.util.List;
import java.util.Map;

public interface PlatformDiagnosticRepository {

    Map<String, Object> database();

    List<Map<String, Object>> vectorExtension();
}
