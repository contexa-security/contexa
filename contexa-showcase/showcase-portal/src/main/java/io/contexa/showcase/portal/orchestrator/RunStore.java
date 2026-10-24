package io.contexa.showcase.portal.orchestrator;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.contexa.showcase.portal.agent.AgentTaskProof;
import io.contexa.showcase.portal.agent.AgentWork;
import io.contexa.showcase.portal.orchestrator.ControlEndpoints.Control;
import io.contexa.showcase.portal.orchestrator.ControlSession.StepOutcome;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Timestamp;
import java.util.HexFormat;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;
import java.util.UUID;

/**
 * Portal storage of runs: the run, each control's step outcome, control D's decisions, the business evidence and
 * the model usage (deck p.24 evidence chain, P1-OPS-01 measurement).
 */
public class RunStore {

    private final NamedParameterJdbcTemplate jdbc;
    private final ObjectMapper json;

    public RunStore(NamedParameterJdbcTemplate jdbc, ObjectMapper json) {
        this.jdbc = jdbc;
        this.json = json;
    }

    /**
     * @param forcedAction       development-only forced decision of the run, null for every real run
     * @param scenarioDefinition the scenario definition the run executes, ground truth included (F-19), as JSON
     * @param scenarioSha256     SHA-256 of that JSON
     */
    public record RunStart(String runId, String scenarioKey, int scenarioVersion, String employeeKey, String principal,
                           String templateId, String organizationId, String tenantId, String clientIp, String device,
                           Instant companyTime, String forcedAction, String liveVisitorHash,
                           String scenarioDefinition, String scenarioSha256) {
    }

    public void start(RunStart run) {
        jdbc.update("""
                        insert into run (run_id, scenario_key, scenario_version, employee_key, principal, template_id,
                                         organization_id, tenant_id, client_ip, device, company_time, status, forced_action,
                                         live_visitor_hash, live_run, scenario_definition, scenario_sha256)
                        values (:run, :scenario, :version, :employee, :principal, :template, :org, :tenant, :ip,
                                :device, :time, 'RUNNING', :forced, :visitor, :live, cast(:definition as jsonb),
                                :definitionSha)""",
                new MapSqlParameterSource("run", run.runId()).addValue("scenario", run.scenarioKey())
                        .addValue("version", run.scenarioVersion()).addValue("employee", run.employeeKey())
                        .addValue("principal", run.principal()).addValue("template", run.templateId())
                        .addValue("org", run.organizationId()).addValue("tenant", run.tenantId())
                        .addValue("ip", run.clientIp()).addValue("device", run.device())
                        .addValue("time", Timestamp.from(run.companyTime()))
                        .addValue("forced", run.forcedAction()).addValue("visitor", run.liveVisitorHash())
                        .addValue("live", run.liveVisitorHash() != null)
                        .addValue("definition", run.scenarioDefinition())
                        .addValue("definitionSha", run.scenarioSha256()));
    }

    public void armResult(String runId, int stepNo, Control control, String operation, StepOutcome outcome) {
        jdbc.update("""
                        insert into run_arm_result (run_id, step_no, control, request_id, operation, method, path,
                                                    company_time, http_status, outcome, delivered_items, rule_id,
                                                    reason, response_excerpt, elapsed_ms, sent_at, stream)
                        values (:run, :step, :control, :request, :operation, :method, :path, :time, :status,
                                :outcome, :delivered, :rule, :reason, :excerpt, :elapsed, :sent,
                                cast(:stream as jsonb))""",
                new MapSqlParameterSource("run", runId).addValue("step", stepNo).addValue("control", control.name())
                        .addValue("request", UUID.fromString(outcome.requestId())).addValue("operation", operation)
                        .addValue("method", outcome.method()).addValue("path", outcome.path())
                        .addValue("time", Timestamp.from(outcome.companyTime()))
                        .addValue("status", outcome.httpStatus()).addValue("outcome", outcome.outcome())
                        .addValue("delivered", outcome.deliveredItems()).addValue("rule", truncate(outcome.ruleId(), 48))
                        .addValue("reason", truncate(outcome.reason(), 500)).addValue("excerpt", outcome.excerpt())
                        .addValue("elapsed", outcome.elapsedMs()).addValue("sent", Timestamp.from(outcome.sentAt()))
                        .addValue("stream", streamJson(outcome.stream())));
    }

    /** Compact form of a stream's progress: samples are [ms since sent, delivered items] pairs. */
    private String streamJson(ExportStreamReader.Progress progress) {
        if (progress == null) {
            return null;
        }
        ObjectNode node = json.createObjectNode();
        if (progress.total() != null) {
            node.put("total", progress.total());
        } else {
            node.putNull("total");
        }
        node.put("delivered", progress.delivered());
        if (progress.firstLineMs() != null) {
            node.put("firstLineMs", progress.firstLineMs());
        } else {
            node.putNull("firstLineMs");
        }
        node.put("endMs", progress.endMs());
        if (progress.cut() != null) {
            node.put("cut", progress.cut());
        } else {
            node.putNull("cut");
        }
        node.put("interrupted", progress.interrupted());
        ArrayNode samples = node.putArray("samples");
        for (ExportStreamReader.Sample sample : progress.samples()) {
            samples.addArray().add(sample.atMs()).add(sample.items());
        }
        return node.toString();
    }

    public void challenge(String runId, int stepNo, String requestId, ControlSession.ChallengeTrace trace,
                          Boolean reanalysed) {
        StepOutcome reissue = trace.reissue();
        jdbc.update("""
                        insert into run_challenge (run_id, step_no, request_id, challenged_at, answered, reason,
                                                   code_requested_at, verified_at, reissue_request_id, reissue_sent_at,
                                                   reissue_status, reissue_outcome, reissue_delivered,
                                                   reissue_elapsed_ms, reissue_reanalysed)
                        values (:run, :step, :request, :challenged, :answered, :reason, :requested, :verified,
                                :reissue, :reissueSent, :status, :outcome, :delivered, :elapsed, :reanalysed)""",
                new MapSqlParameterSource("run", runId).addValue("step", stepNo)
                        .addValue("request", UUID.fromString(requestId))
                        .addValue("challenged", Timestamp.from(trace.challengedAt()))
                        .addValue("answered", trace.answered()).addValue("reason", truncate(trace.reason(), 200))
                        .addValue("requested", timestamp(trace.codeRequestedAt()))
                        .addValue("verified", timestamp(trace.verifiedAt()))
                        .addValue("reissue", reissue == null ? null : UUID.fromString(reissue.requestId()))
                        .addValue("reissueSent", reissue == null ? null : Timestamp.from(reissue.sentAt()))
                        .addValue("status", reissue == null ? null : reissue.httpStatus())
                        .addValue("outcome", reissue == null ? null : reissue.outcome())
                        .addValue("delivered", reissue == null ? null : reissue.deliveredItems())
                        .addValue("elapsed", reissue == null ? null : reissue.elapsedMs())
                        .addValue("reanalysed", reanalysed));
    }

    /** A release from a block of control D (F-23): the whole trace, the engine's block record included. */
    public void release(String runId, int stepNo, String requestId, ControlSession.ReleaseTrace trace) {
        StepOutcome reissue = trace.reissue();
        jdbc.update("""
                        insert into run_release (run_id, step_no, request_id, released, reason, blocked_at,
                                                 code_requested_at, verified_at, requested_at, approved_at,
                                                 block_record, reissue_request_id, reissue_sent_at, reissue_status,
                                                 reissue_outcome, reissue_delivered, reissue_elapsed_ms)
                        values (:run, :step, :request, :released, :reason, :blocked, :codeRequested, :verified,
                                :requested, :approved, cast(:block as jsonb), :reissue, :reissueSent, :status, :outcome,
                                :delivered, :elapsed)
                        on conflict (run_id, step_no) do nothing""",
                new MapSqlParameterSource("run", runId).addValue("step", stepNo)
                        .addValue("request", requestId == null ? null : UUID.fromString(requestId))
                        .addValue("released", trace.released()).addValue("reason", truncate(trace.reason(), 200))
                        .addValue("blocked", timestamp(trace.blockedAt()))
                        .addValue("codeRequested", timestamp(trace.codeRequestedAt()))
                        .addValue("verified", timestamp(trace.verifiedAt()))
                        .addValue("requested", timestamp(trace.requestedAt()))
                        .addValue("approved", timestamp(trace.approvedAt()))
                        .addValue("block", trace.block() == null ? null : write(trace.block()))
                        .addValue("reissue", reissue == null ? null : UUID.fromString(reissue.requestId()))
                        .addValue("reissueSent", reissue == null ? null : Timestamp.from(reissue.sentAt()))
                        .addValue("status", reissue == null ? null : reissue.httpStatus())
                        .addValue("outcome", reissue == null ? null : reissue.outcome())
                        .addValue("delivered", reissue == null ? null : reissue.deliveredItems())
                        .addValue("elapsed", reissue == null ? null : reissue.elapsedMs()));
    }

    /**
     * Stores every model call control D kept for a decision (W1-3b): the system prompt once per hash, then each call.
     * A call collected again (the run's final collection) replaces the earlier copy, so a retry that came late is
     * kept too. Returns the number of calls stored.
     */
    public int exchanges(String runId, int stepNo, String requestId, JsonNode exchanges) {
        if (requestId == null || !exchanges.isArray()) {
            return 0;
        }
        int stored = 0;
        for (JsonNode exchange : exchanges) {
            String system = text(exchange, "systemPrompt");
            String systemSha = system == null ? null : sha256(system);
            if (systemSha != null) {
                jdbc.update("""
                                insert into run_system_prompt (system_prompt_sha256, prompt_text)
                                values (:sha, :text) on conflict (system_prompt_sha256) do nothing""",
                        new MapSqlParameterSource("sha", systemSha).addValue("text", system));
            }
            JsonNode options = exchange.get("requestOptions");
            jdbc.update("""
                            insert into run_model_exchange (request_id, call_no, run_id, step_no, model,
                                                            system_prompt_sha256, user_prompt, answer, finish_reason,
                                                            prompt_tokens, completion_tokens, reasoning_tokens,
                                                            elapsed_ms, success, failure, request_options, http_status,
                                                            provider_response, masked_places, finished_at)
                            values (:request, :call, :run, :step, :model, :system, :user, :answer, :finish, :prompt,
                                    :completion, :reasoning, :elapsed, :success, :failure, cast(:options as jsonb),
                                    :http, :provider, :masked, :finished)
                            on conflict (request_id, call_no) do update set
                                model = excluded.model, system_prompt_sha256 = excluded.system_prompt_sha256,
                                user_prompt = excluded.user_prompt, answer = excluded.answer,
                                finish_reason = excluded.finish_reason, prompt_tokens = excluded.prompt_tokens,
                                completion_tokens = excluded.completion_tokens,
                                reasoning_tokens = excluded.reasoning_tokens, elapsed_ms = excluded.elapsed_ms,
                                success = excluded.success, failure = excluded.failure,
                                request_options = excluded.request_options, http_status = excluded.http_status,
                                provider_response = excluded.provider_response,
                                masked_places = excluded.masked_places, finished_at = excluded.finished_at""",
                    new MapSqlParameterSource("request", UUID.fromString(requestId))
                            .addValue("call", exchange.path("callNo").asInt())
                            .addValue("run", runId).addValue("step", stepNo)
                            .addValue("model", text(exchange, "model")).addValue("system", systemSha)
                            .addValue("user", text(exchange, "userPrompt")).addValue("answer", text(exchange, "answer"))
                            .addValue("finish", truncate(text(exchange, "finishReason"), 32))
                            .addValue("prompt", longValue(exchange, "promptTokens"))
                            .addValue("completion", longValue(exchange, "completionTokens"))
                            .addValue("reasoning", longValue(exchange, "reasoningTokens"))
                            .addValue("elapsed", longValue(exchange, "elapsedMs"))
                            .addValue("success", exchange.path("success").asBoolean(false))
                            .addValue("failure", truncate(text(exchange, "failure"), 120))
                            .addValue("options", options == null || options.isNull() ? null : write(options))
                            .addValue("http", exchange.hasNonNull("httpStatus") ? exchange.path("httpStatus").asInt()
                                    : null)
                            .addValue("provider", text(exchange, "providerResponse"))
                            .addValue("masked", exchange.path("maskedSessionIds").asInt(0))
                            .addValue("finished", exchange.hasNonNull("finishedAt")
                                    ? Timestamp.from(Instant.parse(exchange.path("finishedAt").asText())) : null));
            stored++;
        }
        return stored;
    }

    private static String text(JsonNode node, String field) {
        JsonNode value = node.get(field);
        return value == null || value.isNull() ? null : value.asText();
    }

    private static Long longValue(JsonNode node, String field) {
        JsonNode value = node.get(field);
        return value == null || value.isNull() ? null : value.asLong();
    }

    static String sha256(String text) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(text.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }

    private static Timestamp timestamp(Instant instant) {
        return instant == null ? null : Timestamp.from(instant);
    }

    public void decision(String runId, int stepNo, String requestId, EngineDecision decision) {
        jdbc.update("""
                        insert into run_decision (request_id, run_id, step_no, final_action, proposed_action, risk_score,
                                                  confidence, technical_fallback, success, failure_type,
                                                  fallback_category, reasoning, mitre, applied, total_analysis_ms,
                                                  llm_latency_ms, prompt_tokens, completion_tokens, total_tokens,
                                                  model_calls, decided_at, records, events, parser_failure,
                                                  unresolved)
                        values (:request, :run, :step, :final, :proposed, :risk, :confidence, :fallback, :success,
                                :failure, :category, :reasoning, :mitre, :applied, :total, :llm, :prompt, :completion,
                                :tokens, :calls, :decided, cast(:records as jsonb), cast(:events as jsonb), :parser,
                                :unresolved)""",
                new MapSqlParameterSource("request", UUID.fromString(requestId)).addValue("run", runId)
                        .addValue("step", stepNo).addValue("final", decision.finalAction())
                        .addValue("proposed", decision.proposedAction()).addValue("risk", decision.riskScore())
                        .addValue("confidence", decision.confidence())
                        .addValue("fallback", decision.technicalFallback()).addValue("success", decision.success())
                        .addValue("failure", decision.failureType()).addValue("category", decision.fallbackCategory())
                        .addValue("reasoning", decision.reasoning()).addValue("mitre", decision.mitre())
                        .addValue("applied", decision.applied()).addValue("total", decision.totalAnalysisMs())
                        .addValue("llm", decision.llmLatencyMs()).addValue("prompt", decision.promptTokens())
                        .addValue("completion", decision.completionTokens()).addValue("tokens", decision.totalTokens())
                        .addValue("calls", decision.modelCalls())
                        .addValue("decided", decision.decidedAt() == null ? null : Timestamp.from(decision.decidedAt()))
                        .addValue("records", write(decision.raw().path("records")))
                        .addValue("events", write(decision.raw().path("events")))
                        .addValue("parser", decision.parserFailure()).addValue("unresolved", decision.unresolved()));
    }

    public void businessEvidence(String runId, JsonNode evidence) {
        jdbc.update("""
                        insert into run_business_evidence (run_id, exports, rule_decisions)
                        values (:run, cast(:exports as jsonb), cast(:rules as jsonb))
                        on conflict (run_id) do nothing""",
                new MapSqlParameterSource("run", runId).addValue("exports", write(evidence.path("exports")))
                        .addValue("rules", write(evidence.path("ruleDecisions"))));
    }

    /** What the engine learned during the run (V13 run_learning, R-32). */
    public void learning(String runId, String templateId, JsonNode learning) {
        jdbc.update("""
                        insert into run_learning (run_id, template_id, learning)
                        values (:run, :template, cast(:learning as jsonb))
                        on conflict (run_id) do update set learning = excluded.learning,
                            captured_at = now()""",
                new MapSqlParameterSource("run", runId).addValue("template", templateId)
                        .addValue("learning", write(learning)));
    }

    /**
     * docs/agent A7-2e: the business agent's work of an agent task run, with what it proves per control. The agent's
     * own model use stays here, apart from the engine's cost ledger.
     */
    public void agentTask(String runId, String sender, AgentWork.Transcript transcript, AgentTaskProof.Proof proof) {
        jdbc.update("""
                        insert into run_agent_task (run_id, sender, model, system_prompt, instruction, tool_calls,
                                                    final_answer, stop_reason, failure, agent_usage, proof,
                                                    started_at, finished_at)
                        values (:run, :sender, :model, :prompt, :instruction, cast(:calls as jsonb), :answer, :stop,
                                :failure, cast(:usage as jsonb), cast(:proof as jsonb), :started, :finished)""",
                new MapSqlParameterSource("run", runId).addValue("sender", sender)
                        .addValue("model", truncate(transcript.model(), 64))
                        .addValue("prompt", transcript.systemPrompt()).addValue("instruction", transcript.instruction())
                        .addValue("calls", write(transcript.toolCalls())).addValue("answer", transcript.finalAnswer())
                        .addValue("stop", transcript.stopReason()).addValue("failure", truncate(transcript.failure(), 500))
                        .addValue("usage", write(transcript.usage())).addValue("proof", write(proof))
                        .addValue("started", Timestamp.from(transcript.startedAt()))
                        .addValue("finished", Timestamp.from(transcript.finishedAt())));
    }

    /**
     * docs/agent A7-3: what became of the confirmation control D asked of the agent's work: the delegating person's
     * answer, the confirmation as the agent read it after, and the engine's answers to the request sent again with it.
     */
    public void agentConfirmation(String runId, int stepNo, ControlSession.AgentConfirmationTrace trace) {
        jdbc.update("""
                        insert into run_agent_confirmation (run_id, step_no, confirmation_id, trigger, expires_at,
                                                            decision, reason, asked_at, decided_at, decide_status,
                                                            status_after, resend, reuse, other, person_request,
                                                            retries)
                        values (:run, :step, :id, :trigger, :expires, :decision, :reason, :asked, :decided, :decideStatus,
                                cast(:after as jsonb), cast(:resend as jsonb), cast(:reuse as jsonb),
                                cast(:other as jsonb), cast(:person as jsonb), cast(:retries as jsonb))
                        on conflict (run_id) do nothing""",
                new MapSqlParameterSource("run", runId).addValue("step", stepNo)
                        .addValue("id", truncate(trace.confirmationId(), 64))
                        .addValue("trigger", truncate(trace.trigger(), 40))
                        .addValue("expires", truncate(trace.expiresAt(), 40))
                        .addValue("decision", trace.decision())
                        .addValue("reason", truncate(trace.reason(), 300))
                        .addValue("asked", timestamp(trace.askedAt()))
                        .addValue("decided", timestamp(trace.decidedAt()))
                        .addValue("decideStatus", trace.decideStatus())
                        .addValue("after", trace.after() == null ? null : write(trace.after()))
                        .addValue("resend", trace.resend() == null ? null : write(trace.resend()))
                        .addValue("reuse", trace.reuse() == null ? null : write(trace.reuse()))
                        .addValue("other", trace.other() == null ? null : write(trace.other()))
                        .addValue("person", trace.personRequest() == null ? null : write(trace.personRequest()))
                        .addValue("retries", trace.retries() == null ? null : write(trace.retries())));
    }

    /** docs/agent A7-3: the confirmation record of a run, as stored; empty when control D asked none. */
    public Optional<Map<String, Object>> agentConfirmation(String runId) {
        return jdbc.queryForList("""
                        select run_id, step_no, confirmation_id, trigger, expires_at, decision, reason, asked_at,
                               decided_at, decide_status, status_after::text as status_after, resend::text as resend,
                               reuse::text as reuse, other::text as other, person_request::text as person_request,
                               retries::text as retries
                          from run_agent_confirmation where run_id = :run""", new MapSqlParameterSource("run", runId))
                .stream().findFirst().map(row -> {
                    Map<String, Object> view = new LinkedHashMap<>();
                    view.put("stepNo", row.get("step_no"));
                    view.put("confirmationId", row.get("confirmation_id"));
                    view.put("trigger", row.get("trigger"));
                    view.put("expiresAt", row.get("expires_at"));
                    view.put("decision", row.get("decision"));
                    view.put("reason", row.get("reason"));
                    view.put("askedAt", row.get("asked_at"));
                    view.put("decidedAt", row.get("decided_at"));
                    view.put("decideStatus", row.get("decide_status"));
                    Map<String, String> fields = new LinkedHashMap<>();
                    fields.put("status_after", "after");
                    fields.put("resend", "resend");
                    fields.put("reuse", "reuse");
                    fields.put("other", "other");
                    fields.put("person_request", "personRequest");
                    fields.put("retries", "retries");
                    fields.forEach((column, name) -> {
                        String value = (String) row.get(column);
                        view.put(name, value == null ? null : read(value));
                    });
                    return view;
                });
    }

    /**
     * docs/agent A7-3: the latest completed recording of an agent case definition (by its definition hash): an
     * operator's run, never a visitor's or one with a forced decision.
     */
    public Optional<Map<String, Object>> latestRecordedAgentRun(String definitionSha256) {
        return jdbc.queryForList("""
                        select r.run_id, r.started_at from run r
                          join run_agent_task t on t.run_id = r.run_id
                         where r.scenario_sha256 = :sha and r.status = 'COMPLETED' and r.forced_action is null
                           and r.live_visitor_hash is null
                         order by r.started_at desc limit 1""", new MapSqlParameterSource("sha", definitionSha256))
                .stream().findFirst();
    }

    /** docs/agent A7-2f: the agent task record of a run, as stored; empty for a run of scripted steps. */
    public Optional<Map<String, Object>> agentTask(String runId) {
        return jdbc.queryForList("""
                        select run_id, sender, model, system_prompt, instruction, tool_calls::text as tool_calls,
                               final_answer, stop_reason, failure, agent_usage::text as agent_usage, proof::text as proof,
                               started_at, finished_at
                          from run_agent_task where run_id = :run""", new MapSqlParameterSource("run", runId))
                .stream().findFirst();
    }

    /**
     * docs/agent A7-2f: what an agent task run shows: the work (what was asked, how it ended, the agent's answer), what
     * it proves per control, every step with the tool that sent it, the five controls' outcomes and control D's
     * decision, and its cost (the agent's tokens, the decision models' calls and tokens). Empty for a run of scripted
     * steps only.
     */
    public Optional<Map<String, Object>> agentTaskSummary(String runId) {
        Optional<Map<String, Object>> stored = agentTask(runId);
        if (stored.isEmpty()) {
            return Optional.empty();
        }
        Map<String, Object> row = stored.get();
        MapSqlParameterSource run = new MapSqlParameterSource("run", runId);
        Map<Integer, JsonNode> toolOfStep = new LinkedHashMap<>();
        for (JsonNode call : read((String) row.get("tool_calls"))) {
            if (call.path("sent").asBoolean() && call.path("answer").has("stepNo")) {
                ObjectNode tool = json.createObjectNode();
                tool.put("tool", call.path("tool").asText());
                tool.set("arguments", call.path("arguments"));
                toolOfStep.put(call.path("answer").path("stepNo").asInt(), tool);
            }
        }
        Map<Integer, Map<String, Object>> steps = new TreeMap<>();
        for (Map<String, Object> arm : jdbc.queryForList("""
                select step_no, control, path, outcome, delivered_items, rule_id, company_time
                  from run_arm_result where run_id = :run order by step_no, control""", run)) {
            int stepNo = ((Number) arm.get("step_no")).intValue();
            Map<String, Object> step = steps.computeIfAbsent(stepNo, number -> {
                Map<String, Object> value = new LinkedHashMap<>();
                value.put("stepNo", number);
                value.put("sentBy", toolOfStep.containsKey(number) ? "AGENT_WORK" : "SCRIPT");
                value.put("tool", toolOfStep.get(number));
                value.put("path", arm.get("path"));
                // docs/agent A7-3: the company time the step went at, as every control received it.
                value.put("companyTime", arm.get("company_time"));
                value.put("outcomes", new LinkedHashMap<String, Object>());
                return value;
            });
            Map<String, Object> outcome = new LinkedHashMap<>();
            outcome.put("outcome", arm.get("outcome"));
            outcome.put("deliveredItems", arm.get("delivered_items"));
            outcome.put("rule", arm.get("rule_id"));
            @SuppressWarnings("unchecked")
            Map<String, Object> outcomes = (Map<String, Object>) step.get("outcomes");
            outcomes.put((String) arm.get("control"), outcome);
        }
        for (Map<String, Object> decision : jdbc.queryForList("""
                select step_no, request_id, final_action, proposed_action, risk_score, confidence, model_calls,
                       total_tokens, technical_fallback
                  from run_decision where run_id = :run order by step_no""", run)) {
            Map<String, Object> step = steps.get(((Number) decision.get("step_no")).intValue());
            if (step != null) {
                step.put("decision", decision);
            }
        }
        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("runId", runId);
        summary.put("sender", row.get("sender"));
        summary.put("agentModel", row.get("model"));
        summary.put("instruction", row.get("instruction"));
        summary.put("systemPrompt", row.get("system_prompt"));
        summary.put("stopReason", row.get("stop_reason"));
        summary.put("failure", row.get("failure"));
        summary.put("finalAnswer", row.get("final_answer"));
        summary.put("startedAt", row.get("started_at"));
        // docs/agent A7-3: the run's company time, which the case's fact offsets (a delegation's period) count from.
        summary.put("companyTime", jdbc.queryForList("select company_time from run where run_id = :run", run)
                .stream().findFirst().map(found -> found.get("company_time")).orElse(null));
        summary.put("finishedAt", row.get("finished_at"));
        summary.put("proof", read((String) row.get("proof")));
        summary.put("steps", List.copyOf(steps.values()));
        summary.put("confirmation", agentConfirmation(runId).orElse(null));
        Map<String, Object> cost = new LinkedHashMap<>();
        cost.put("agent", read((String) row.get("agent_usage")));
        cost.put("decisions", jdbc.queryForList("""
                select model, count(*) as calls, sum(prompt_tokens) as prompt_tokens,
                       sum(completion_tokens) as completion_tokens, sum(total_tokens) as total_tokens
                  from cost_ledger where run_id = :run group by model order by model""", run));
        summary.put("cost", cost);
        return Optional.of(summary);
    }

    private JsonNode read(String value) {
        try {
            return value == null ? json.nullNode() : json.readTree(value);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Unreadable stored evidence", e);
        }
    }

    public void cost(String runId, String templateId, String requestId, JsonNode call) {
        jdbc.update("""
                        insert into cost_ledger (entry_id, run_id, template_id, request_id, kind, model, prompt_tokens,
                                                 completion_tokens, total_tokens, elapsed_ms)
                        values (:id, :run, :template, :request, :kind, :model, :prompt, :completion, :total, :elapsed)""",
                new MapSqlParameterSource("id", UUID.randomUUID()).addValue("run", runId)
                        .addValue("template", templateId)
                        .addValue("request", requestId == null ? null : UUID.fromString(requestId))
                        .addValue("kind", call.path("kind").asText("CHAT")).addValue("model", call.path("model").asText(null))
                        .addValue("prompt", call.path("promptTokens").asLong(0))
                        .addValue("completion", call.path("completionTokens").asLong(0))
                        .addValue("total", call.path("totalTokens").asLong(0))
                        .addValue("elapsed", call.path("elapsedMs").asLong(0)));
    }

    public void spec(String runId, String specHash) {
        spec(runId, specHash, null);
    }

    /** The run's execution specification and its measurement setting (W5, V-13). */
    public void spec(String runId, String specHash, String settingHash) {
        jdbc.update("update run set spec_hash = :hash, setting_hash = :setting where run_id = :run",
                new MapSqlParameterSource("run", runId).addValue("hash", specHash).addValue("setting", settingHash));
    }

    /** A measurement protocol starts: every listed case, {@code repeat} times (W5-0). */
    public void protocolStarted(String protocolId, int repeat, List<String> cases) {
        jdbc.update("""
                        insert into measurement_protocol (protocol_id, repeat, cases, started_at)
                        values (:id, :repeat, cast(:cases as jsonb), now())""",
                new MapSqlParameterSource("id", protocolId).addValue("repeat", repeat)
                        .addValue("cases", write(cases)));
    }

    /** Marks a finished run as one of the protocol's runs. */
    public void protocolRun(String protocolId, String runId) {
        jdbc.update("update run set protocol_id = :id where run_id = :run",
                new MapSqlParameterSource("id", protocolId).addValue("run", runId));
    }

    public void protocolFinished(String protocolId) {
        jdbc.update("update measurement_protocol set finished_at = now() where protocol_id = :id",
                new MapSqlParameterSource("id", protocolId));
    }

    /**
     * Closes the protocols a stopped portal left unfinished (벤치마크 계획 BM-S9): a protocol's job lives in the portal
     * that ran it, so no more runs come to them; each ends at its last run, or at its start when none ran.
     */
    public int closeUnfinishedProtocols() {
        return jdbc.update("""
                        update measurement_protocol p
                           set finished_at = coalesce((select max(coalesce(r.finished_at, r.started_at)) from run r
                                                        where r.protocol_id = p.protocol_id), p.started_at)
                         where p.finished_at is null""", new MapSqlParameterSource());
    }

    public void finish(String runId, String status, String failure, Map<String, Object> cleanup) {
        jdbc.update("""
                        update run set status = :status, failure = :failure, cleanup = cast(:cleanup as jsonb),
                                       finished_at = now()
                         where run_id = :run""",
                new MapSqlParameterSource("run", runId).addValue("status", status)
                        .addValue("failure", truncate(failure, 500)).addValue("cleanup", write(cleanup)));
    }

    /**
     * A run whose clean-up has to be done again: a finished run whose engine or business clean-up failed, or a run
     * still RUNNING long after any run could last (the portal stopped during the run).
     *
     * @param cleanup the recorded clean-up result as JSON text, null when the run never got that far
     */
    public record CleanupCandidate(String runId, String principal, String status, String cleanup) {
    }

    public List<CleanupCandidate> cleanupCandidates(Instant abandonedBefore, int maxRetries, int limit) {
        return jdbc.query("""
                        select run_id, principal, status, cleanup::text from run
                         where (status <> 'RUNNING'
                                and (cleanup ->> 'engineError' is not null or cleanup ->> 'businessError' is not null)
                                and coalesce((cleanup ->> 'retries')::int, 0) < :maxRetries)
                            or (status = 'RUNNING' and started_at < :abandoned)
                         order by started_at limit :limit""",
                new MapSqlParameterSource("abandoned", Timestamp.from(abandonedBefore))
                        .addValue("maxRetries", maxRetries).addValue("limit", limit),
                (rs, n) -> new CleanupCandidate(rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(4)));
    }

    /** Stores the result of a repeated clean-up; an abandoned RUNNING run is closed as FAILED with the reason. */
    public void cleanupRetried(String runId, Map<String, Object> cleanup, String abandonedFailure) {
        jdbc.update("""
                        update run set cleanup = cast(:cleanup as jsonb),
                                       status = case when status = 'RUNNING' then 'FAILED' else status end,
                                       failure = case when status = 'RUNNING' then :failure else failure end,
                                       finished_at = coalesce(finished_at, now())
                         where run_id = :run""",
                new MapSqlParameterSource("run", runId).addValue("cleanup", write(cleanup))
                        .addValue("failure", truncate(abandonedFailure, 500)));
    }

    public Map<String, Object> run(String runId) {
        List<Map<String, Object>> runs = jdbc.queryForList("select * from run where run_id = :run",
                new MapSqlParameterSource("run", runId));
        if (runs.isEmpty()) {
            return Map.of();
        }
        MapSqlParameterSource run = new MapSqlParameterSource("run", runId);
        return Map.of(
                "run", runs.get(0),
                "arms", jdbc.queryForList("""
                        select step_no, control, operation, method, path, company_time, http_status, outcome,
                               delivered_items, rule_id, reason, elapsed_ms, request_id
                          from run_arm_result where run_id = :run order by step_no, control""", run),
                "decisions", jdbc.queryForList("""
                        select step_no, request_id, final_action, proposed_action, risk_score, confidence,
                               technical_fallback, parser_failure, unresolved, success, failure_type,
                               fallback_category, mitre, applied,
                               total_analysis_ms, llm_latency_ms, prompt_tokens, completion_tokens, total_tokens,
                               model_calls, reasoning
                          from run_decision where run_id = :run order by step_no""", run));
    }

    private String write(Object value) {
        try {
            return json.writeValueAsString(value);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Unwritable evidence", e);
        }
    }

    private static String truncate(String value, int length) {
        return value == null || value.length() <= length ? value : value.substring(0, length);
    }
}
