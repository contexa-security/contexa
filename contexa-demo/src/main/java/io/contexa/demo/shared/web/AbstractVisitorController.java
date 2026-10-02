package io.contexa.demo.shared.web;

import io.contexa.demo.entry.domain.Visitor;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import java.util.UUID;

public abstract class AbstractVisitorController extends AbstractQueryController {

    protected UUID visitorId(HttpServletRequest request) {
        Visitor visitor = (Visitor) request.getAttribute(Visitor.class.getName());
        if (visitor == null || !visitor.verified()) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN);
        }
        return visitor.id();
    }
}
