package io.contexa.demo.readiness.repository;

import java.util.List;
import java.util.Map;

public interface DiagnosticRepository {

    Map<String, Object> database();

    List<Map<String, Object>> migrations();

    List<Map<String, Object>> identityScope();
}
