package io.contexa.showcase.portal.journey;

import io.contexa.showcase.portal.visitor.VisitorCookies;
import io.contexa.showcase.portal.visitor.VisitorStore;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/** Visitor API of the journey; the visitor is the one of the signed visitor cookie, a change is a POST under CSRF. */
@RestController
public class JourneyController {

    public record QuizRequest(Map<String, String> answers) {
    }

    private final JourneyViews journey;
    private final ActEndCards actEnds;
    private final AnonymousTally tally;
    private final VisitorCookies cookies;
    private final VisitorStore visitors;

    public JourneyController(JourneyViews journey, ActEndCards actEnds, AnonymousTally tally, VisitorCookies cookies,
                             VisitorStore visitors) {
        this.journey = journey;
        this.actEnds = actEnds;
        this.tally = tally;
        this.cookies = cookies;
        this.visitors = visitors;
    }

    /** The anonymous counts still kept: answers right per question and visitors per act (ADR-35). */
    @GetMapping("/api/tally")
    public AnonymousTally.Summary tally() {
        return tally.summary();
    }

    /** The values of the card at the end of an act, from the visitor's own run or the measurement (work 18). */
    @GetMapping("/api/journey/act-end")
    public ResponseEntity<ActEndCards.ActEnd> actEnd(HttpServletRequest request, @RequestParam("act") int act) {
        Optional<String> visitor = cookies.visitorOf(request);
        if (visitor.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        return ResponseEntity.of(actEnds.card(visitor.get(), act));
    }

    /** The quiz questions without their answers. */
    @GetMapping("/api/quiz")
    public List<JourneyViews.QuestionView> questions() {
        return journey.questions();
    }

    /** Scores the visitor's answers on the server (work 15); 400 for an answer that is not an option. */
    @PostMapping("/api/quiz")
    public ResponseEntity<JourneyViews.QuizResult> answer(HttpServletRequest request,
                                                          @RequestBody QuizRequest quiz) {
        Optional<String> visitor = cookies.visitorOf(request);
        if (visitor.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        visitors.touch(visitor.get());
        return journey.answer(visitor.get(), quiz == null ? null : quiz.answers()).map(ResponseEntity::ok)
                .orElse(ResponseEntity.badRequest().build());
    }

    @GetMapping("/api/journey")
    public ResponseEntity<JourneyViews.View> journey(HttpServletRequest request) {
        Optional<String> visitor = cookies.visitorOf(request);
        return visitor.map(hash -> ResponseEntity.ok(journey.view(hash)))
                .orElse(ResponseEntity.status(HttpStatus.UNAUTHORIZED).build());
    }

    @PostMapping("/api/journey")
    public ResponseEntity<JourneyViews.View> update(HttpServletRequest request,
                                                    @RequestBody JourneyViews.Update update) {
        Optional<String> visitor = cookies.visitorOf(request);
        if (visitor.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        visitors.touch(visitor.get());
        return journey.update(visitor.get(), update).map(ResponseEntity::ok)
                .orElse(ResponseEntity.badRequest().build());
    }
}
