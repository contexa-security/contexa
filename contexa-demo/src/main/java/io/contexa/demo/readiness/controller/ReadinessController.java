package io.contexa.demo.readiness.controller;

import io.contexa.demo.readiness.dto.ReadinessCapture;
import io.contexa.demo.readiness.dto.ReadinessReport;
import io.contexa.demo.readiness.dto.StoredReadiness;
import io.contexa.demo.readiness.service.ReadinessService;
import io.contexa.demo.shared.web.AbstractQueryController;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/lab/readiness")
public class ReadinessController extends AbstractQueryController {

    private final ReadinessService service;

    public ReadinessController(ReadinessService service) {
        this.service = service;
    }

    @GetMapping
    public ResponseEntity<ReadinessReport> summary() {
        return result(service.inspect(false, true));
    }

    @GetMapping("/local")
    public ResponseEntity<ReadinessReport> local() {
        return result(service.inspect(false, false));
    }

    @GetMapping("/details")
    public ResponseEntity<ReadinessReport> details() {
        return result(service.inspect(true, true));
    }

    @PostMapping("/snapshots")
    public ResponseEntity<ReadinessCapture> capture() {
        return result(service.capture());
    }

    @GetMapping("/snapshots")
    public ResponseEntity<List<StoredReadiness>> history() {
        return result(service.history());
    }
}
