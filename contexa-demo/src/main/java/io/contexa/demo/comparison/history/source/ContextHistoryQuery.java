package io.contexa.demo.comparison.history.source;

import io.contexa.demo.comparison.history.dto.ContextHistorySnapshot;
import jakarta.servlet.http.HttpServletRequest;

public interface ContextHistoryQuery {

    ContextHistorySnapshot capture(String username, HttpServletRequest request);
}
