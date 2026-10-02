package io.contexa.demo.observation.stream.controller;

import io.contexa.demo.entry.domain.Visitor;
import io.contexa.demo.observation.stream.service.ObservationStream;
import io.contexa.demo.shared.web.AbstractVisitorController;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Profile;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.util.UUID;

@RestController
@Profile("portal")
@RequestMapping("/api/lab/workspaces/requests")
public class ObservationStreamController extends AbstractVisitorController {

    private final ObservationStream stream;

    public ObservationStreamController(ObservationStream stream) {
        this.stream = stream;
    }

    @GetMapping(value = "/{arm}/{id}/events", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public ResponseEntity<SseEmitter> open(@PathVariable String arm, @PathVariable UUID id,
            @RequestParam(defaultValue = "0") long after,
            @RequestHeader(name = "Last-Event-ID", required = false) Long lastEventId,
            HttpServletRequest request) {
        UUID visitorId = visitorId(request);
        Visitor visitor = (Visitor) request.getAttribute(Visitor.class.getName());
        SseEmitter emitter = stream.open(arm, id, visitorId, visitor.expiresAt(),
                lastEventId == null ? after : lastEventId);
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).header("X-Accel-Buffering", "no")
                .body(emitter);
    }
}
