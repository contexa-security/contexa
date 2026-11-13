package io.contexa.contexaiam.admin.promptquality.inspection;

import io.contexa.contexacore.verification.inspection.PromptInspectionReinspection;
import io.contexa.contexacore.verification.inspection.PromptInspectionResult;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import java.time.Clock;
import java.time.Instant;
import java.util.Objects;

/** A capture period to inspect again, both ends included. */
public record PeriodRequest(Instant from, Instant to) {
}
