/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.autoconfigure.ownership;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;
import java.util.List;

/** The host's pages: one it closes, two it leaves open, and what its HTTP session holds. */
@RestController
class GridController {

    static final String SECURED = "/h/secured/data";
    static final String OPEN = "/h/open/info";
    /** A page the host leaves open and a URL policy of Contexa names for administrators. */
    static final String OPEN_STAFF = "/h/open/staff/report";
    static final String SESSION_ATTRIBUTES = "/h/session-attributes";
    /**
     * The sign-in page of a host whose chain is narrowed to its own paths (mode FULL, R-14): Spring's default page would
     * stand at /login, outside its chain.
     */
    static final String HOST_LOGIN = "/h/login";

    @GetMapping(value = HOST_LOGIN, produces = "text/html")
    String hostLogin(HttpServletRequest request) {
        CsrfToken token = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
        return "<form method=\"post\" action=\"" + HOST_LOGIN + "\"><input type=\"hidden\" name=\"_csrf\" value=\""
                + (token != null ? token.getToken() : "") + "\"></form>";
    }

    @GetMapping(SECURED)
    String secured() {
        return "host data";
    }

    @GetMapping(OPEN)
    String open() {
        return "open info";
    }

    @GetMapping(OPEN_STAFF)
    String staff() {
        return "staff report";
    }

    @GetMapping(SESSION_ATTRIBUTES)
    List<String> sessionAttributes(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        return session == null ? List.of() : Collections.list(session.getAttributeNames()).stream().sorted().toList();
    }
}
