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
package io.contexa.autoconfigure.core.hcad;

import io.contexa.contexacommon.annotation.Protectable;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

@AutoConfiguration
@ConditionalOnProperty(prefix = "contexa.hcad.live.verification", name = "enabled", havingValue = "true")
public class HcadLiveVerificationAutoConfiguration {

    public static final String RUN_ID_HEADER = "X-Contexa-Test-Run-Id";

    @Bean
    public HcadLiveVerificationService hcadLiveVerificationService() {
        return new HcadLiveVerificationService();
    }

    public static class HcadLiveVerificationService {

        @Protectable(
                resourceId = "hcad.live.account.detail",
                resourceUrl = "/contexa/test/hcad/live/accounts/{accountId}",
                httpMethod = "GET",
                verificationRequired = false,
                sync = true)
        public Map<String, Object> accountDetail(String accountId, String runId) {
            return response("account-detail", "GET", "/contexa/test/hcad/live/accounts/" + accountId, runId,
                    Map.of("accountId", safe(accountId), "businessArea", "customer-account"));
        }

        @Protectable(
                resourceId = "hcad.live.finance.invoice",
                resourceUrl = "/contexa/test/hcad/live/finance/invoices/{invoiceId}",
                httpMethod = "GET",
                verificationRequired = false,
                sync = true)
        public Map<String, Object> financeInvoice(String invoiceId, String runId) {
            return response("finance-invoice", "GET", "/contexa/test/hcad/live/finance/invoices/" + invoiceId, runId,
                    Map.of("invoiceId", safe(invoiceId), "businessArea", "finance"));
        }

        @Protectable(
                resourceId = "hcad.live.policy.escalation",
                resourceUrl = "/contexa/test/hcad/live/policies/escalation",
                httpMethod = "POST",
                verificationRequired = false,
                sync = true)
        public Map<String, Object> policyEscalation(Map<String, Object> body, String runId) {
            return response("policy-escalation", "POST", "/contexa/test/hcad/live/policies/escalation", runId,
                    Map.of("businessArea", "policy", "payloadKeys", body == null ? 0 : body.size()));
        }

        @Protectable(
                resourceId = "hcad.live.vendor.export",
                resourceUrl = "/contexa/test/hcad/live/vendors/{vendorId}/export",
                httpMethod = "GET",
                verificationRequired = false,
                sync = true)
        public Map<String, Object> vendorExport(String vendorId, String runId) {
            return response("vendor-export", "GET", "/contexa/test/hcad/live/vendors/" + vendorId + "/export", runId,
                    Map.of("vendorId", safe(vendorId), "businessArea", "external-vendor"));
        }

        @Protectable(
                resourceId = "hcad.live.security.incident.close",
                resourceUrl = "/contexa/test/hcad/live/security/incidents/{incidentId}/close",
                httpMethod = "POST",
                verificationRequired = false,
                sync = true)
        public Map<String, Object> closeSecurityIncident(String incidentId, Map<String, Object> body, String runId) {
            return response("security-incident-close", "POST",
                    "/contexa/test/hcad/live/security/incidents/" + incidentId + "/close", runId,
                    Map.of("incidentId", safe(incidentId), "businessArea", "security", "payloadKeys",
                            body == null ? 0 : body.size()));
        }

        @Protectable(
                resourceId = "hcad.live.hr.candidate",
                resourceUrl = "/contexa/test/hcad/live/hr/candidates/{candidateId}",
                httpMethod = "GET",
                verificationRequired = false,
                sync = true)
        public Map<String, Object> hrCandidate(String candidateId, String runId) {
            return response("hr-candidate", "GET", "/contexa/test/hcad/live/hr/candidates/" + candidateId, runId,
                    Map.of("candidateId", safe(candidateId), "businessArea", "human-resources"));
        }

        private Map<String, Object> response(
                String scenario,
                String method,
                String path,
                String runId,
                Map<String, Object> details) {
            Map<String, Object> response = new LinkedHashMap<>();
            response.put("scenario", scenario);
            response.put("method", method);
            response.put("path", path);
            response.put("runId", safe(runId));
            response.put("source", "hcad-live-verification");
            response.put("createdAt", Instant.now().toString());
            response.put("details", details == null ? Map.of() : details);
            return response;
        }

        private static String safe(String value) {
            return StringUtils.hasText(value) ? value.trim() : "";
        }
    }

    @RestController
    @RequestMapping("/contexa/test/hcad/live")
    public static class HcadLiveVerificationController {

        private final HcadLiveVerificationService service;

        public HcadLiveVerificationController(HcadLiveVerificationService service) {
            this.service = service;
        }

        @GetMapping("/accounts/{accountId}")
        public ResponseEntity<Map<String, Object>> accountDetail(
                @PathVariable String accountId,
                HttpServletRequest request,
                @RequestHeader(name = RUN_ID_HEADER, required = false) String runId) {
            return ResponseEntity.ok(service.accountDetail(accountId, runId(request, runId)));
        }

        @GetMapping("/finance/invoices/{invoiceId}")
        public ResponseEntity<Map<String, Object>> financeInvoice(
                @PathVariable String invoiceId,
                HttpServletRequest request,
                @RequestHeader(name = RUN_ID_HEADER, required = false) String runId) {
            return ResponseEntity.ok(service.financeInvoice(invoiceId, runId(request, runId)));
        }

        @PostMapping("/policies/escalation")
        public ResponseEntity<Map<String, Object>> policyEscalation(
                @RequestBody(required = false) Map<String, Object> body,
                HttpServletRequest request,
                @RequestHeader(name = RUN_ID_HEADER, required = false) String runId) {
            return ResponseEntity.ok(service.policyEscalation(body, runId(request, runId)));
        }

        @GetMapping("/vendors/{vendorId}/export")
        public ResponseEntity<Map<String, Object>> vendorExport(
                @PathVariable String vendorId,
                HttpServletRequest request,
                @RequestHeader(name = RUN_ID_HEADER, required = false) String runId) {
            return ResponseEntity.ok(service.vendorExport(vendorId, runId(request, runId)));
        }

        @PostMapping("/security/incidents/{incidentId}/close")
        public ResponseEntity<Map<String, Object>> closeSecurityIncident(
                @PathVariable String incidentId,
                @RequestBody(required = false) Map<String, Object> body,
                HttpServletRequest request,
                @RequestHeader(name = RUN_ID_HEADER, required = false) String runId) {
            return ResponseEntity.ok(service.closeSecurityIncident(incidentId, body, runId(request, runId)));
        }

        @GetMapping("/hr/candidates/{candidateId}")
        public ResponseEntity<Map<String, Object>> hrCandidate(
                @PathVariable String candidateId,
                HttpServletRequest request,
                @RequestHeader(name = RUN_ID_HEADER, required = false) String runId) {
            return ResponseEntity.ok(service.hrCandidate(candidateId, runId(request, runId)));
        }

        private String runId(HttpServletRequest request, String headerValue) {
            if (StringUtils.hasText(headerValue)) {
                return headerValue.trim();
            }
            String parameterValue = request == null ? null : request.getParameter("runId");
            return StringUtils.hasText(parameterValue) ? parameterValue.trim() : "";
        }
    }
}
