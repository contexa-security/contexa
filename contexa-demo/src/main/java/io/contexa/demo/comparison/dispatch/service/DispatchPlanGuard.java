package io.contexa.demo.comparison.dispatch.service;

import io.contexa.demo.comparison.run.dto.RunRecord;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import java.io.IOException;

public interface DispatchPlanGuard {

    byte[] verify(RunRecord run, Authentication authentication, HttpServletRequest request) throws IOException;
}
