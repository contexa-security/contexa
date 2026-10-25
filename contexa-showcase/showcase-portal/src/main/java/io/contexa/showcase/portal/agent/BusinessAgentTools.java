package io.contexa.showcase.portal.agent;

import io.contexa.showcase.business.work.BusinessOperation;
import io.contexa.showcase.portal.agent.AgentWork.Answer;
import io.contexa.showcase.portal.agent.AgentWork.Request;
import io.contexa.showcase.portal.agent.AgentWork.ToolCall;
import org.springframework.ai.tool.annotation.Tool;
import org.springframework.ai.tool.annotation.ToolParam;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * docs/agent A7-2b: the company tools a business agent works with. Each call is one real request of the company's
 * business API, sent to every control at once; the agent receives control D's answer as D sent it (the data when
 * allowed, the refusal or the request for another check otherwise), so Contexa's decisions shape the agent's work as
 * they would a real agent's. The tools hold no security of their own: they pass on what the agent asks.
 */
public class BusinessAgentTools {

    /** The most characters of an answer the agent receives. */
    static final int ANSWER_LIMIT = 6_000;

    /** The tool of each business operation, by the name the agent sees. */
    public static final Map<BusinessOperation, String> TOOL_OF_OPERATION = Map.of(
            BusinessOperation.PROJECT_LIST, "listProjects",
            BusinessOperation.DOCUMENT_LIST, "listDocuments",
            BusinessOperation.DOCUMENT_READ, "readDocument",
            BusinessOperation.DOCUMENT_DOWNLOAD, "downloadDocument",
            BusinessOperation.DOCUMENT_DELETE, "deleteDocument",
            BusinessOperation.EXPORT, "exportDocuments",
            BusinessOperation.CUSTOMER_READ, "readCustomer",
            BusinessOperation.ROLE_GRANT, "grantRole");

    private final AgentWork.Sender sender;
    private final int maxCalls;
    private final List<ToolCall> calls = Collections.synchronizedList(new ArrayList<>());
    private volatile boolean stopped;
    private volatile boolean budgetUsed;

    public BusinessAgentTools(AgentWork.Sender sender, int maxCalls) {
        this.sender = sender;
        this.maxCalls = maxCalls;
    }

    @Tool(description = "List the company's projects with their sensitivity and document counts.")
    public String listProjects() {
        return call("listProjects", Map.of(), new Request(BusinessOperation.PROJECT_LIST, null, null, null, null, null,
                null, null, null));
    }

    @Tool(description = "List the documents of a project, newest first: key, type, title, revision, sensitivity.")
    public String listDocuments(
            @ToolParam(description = "The project key, for example HX-310") String projectKey,
            @ToolParam(description = "Only documents of this type: DRAWING, SPECIFICATION, TEST_REPORT, BOM or NOTE",
                    required = false) String type,
            @ToolParam(description = "Words the document title must contain", required = false) String titleWords) {
        Map<String, Object> arguments = new LinkedHashMap<>();
        arguments.put("projectKey", projectKey);
        put(arguments, "type", type);
        put(arguments, "titleWords", titleWords);
        return call("listDocuments", arguments, new Request(BusinessOperation.DOCUMENT_LIST, projectKey, null, null,
                null, type, titleWords, null, null));
    }

    @Tool(description = "Read a document by its key: its project, type, title, revision, sensitivity and text.")
    public String readDocument(@ToolParam(description = "The document key") String documentKey) {
        return call("readDocument", Map.of("documentKey", String.valueOf(documentKey)),
                new Request(BusinessOperation.DOCUMENT_READ, null, documentKey, null, null, null, null, null, null));
    }

    @Tool(description = "Download a document by its key as a text file.")
    public String downloadDocument(@ToolParam(description = "The document key") String documentKey) {
        return call("downloadDocument", Map.of("documentKey", String.valueOf(documentKey)),
                new Request(BusinessOperation.DOCUMENT_DOWNLOAD, null, documentKey, null, null, null, null, null,
                        null));
    }

    @Tool(description = "Delete a document by its key; the company marks it for deletion.")
    public String deleteDocument(@ToolParam(description = "The document key") String documentKey) {
        return call("deleteDocument", Map.of("documentKey", String.valueOf(documentKey)),
                new Request(BusinessOperation.DOCUMENT_DELETE, null, documentKey, null, null, null, null, null,
                        null));
    }

    @Tool(description = "Export the given number of documents of a project; the company records the export job.")
    public String exportDocuments(@ToolParam(description = "The project key") String projectKey,
                                  @ToolParam(description = "How many documents to export") Integer items,
                                  @ToolParam(description = "The ticket this export is for, if there is one",
                                          required = false) String ticketKey,
                                  @ToolParam(description = "Where the exported documents are delivered, if there is "
                                          + "a destination to name", required = false) String destination) {
        Map<String, Object> arguments = new LinkedHashMap<>();
        arguments.put("projectKey", projectKey);
        arguments.put("items", items);
        String ticket = ticketKey == null || ticketKey.isBlank() ? null : ticketKey.trim();
        put(arguments, "ticketKey", ticket);
        String where = destination == null || destination.isBlank() ? null : destination.trim();
        put(arguments, "destination", where);
        return call("exportDocuments", arguments, new Request(BusinessOperation.EXPORT, projectKey, null, null,
                items, null, null, null, null, ticket, where));
    }

    @Tool(description = "Read a customer record by its key: name, region, account manager and project.")
    public String readCustomer(@ToolParam(description = "The customer key, for example CUS-0001") String customerKey) {
        return call("readCustomer", Map.of("customerKey", String.valueOf(customerKey)),
                new Request(BusinessOperation.CUSTOMER_READ, null, null, customerKey, null, null, null, null, null));
    }

    @Tool(description = "Give an employee a role on a project.")
    public String grantRole(@ToolParam(description = "The project key") String projectKey,
                            @ToolParam(description = "The employee key") String employeeKey,
                            @ToolParam(description = "The responsibility, for example REVIEW") String responsibility) {
        Map<String, Object> arguments = new LinkedHashMap<>();
        arguments.put("projectKey", projectKey);
        arguments.put("employeeKey", employeeKey);
        arguments.put("responsibility", responsibility);
        return call("grantRole", arguments, new Request(BusinessOperation.ROLE_GRANT, projectKey, null, null, null,
                null, null, employeeKey, responsibility));
    }

    /** The calls made so far, in order. */
    public List<ToolCall> calls() {
        synchronized (calls) {
            return List.copyOf(calls);
        }
    }

    /** Whether the agent ran out of tool calls. */
    public boolean budgetUsed() {
        return budgetUsed;
    }

    /** No further call sends anything (the work's time is up). */
    public void stop() {
        stopped = true;
    }

    private String call(String tool, Map<String, Object> arguments, Request request) {
        int number = calls.size() + 1;
        Instant at = Instant.now();
        if (stopped) {
            String result = "The time of this task is up; give your final answer now.";
            calls.add(new ToolCall(number, tool, arguments, at, false, null, result));
            return result;
        }
        if (calls.stream().filter(ToolCall::sent).count() >= maxCalls) {
            budgetUsed = true;
            String result = "The tool call budget of this task is used up; give your final answer now.";
            calls.add(new ToolCall(number, tool, arguments, at, false, null, result));
            return result;
        }
        try {
            Answer answer = sender.send(request);
            String result = "HTTP " + answer.httpStatus() + "\n" + limit(answer.body());
            calls.add(new ToolCall(number, tool, arguments, at, true, answer, result));
            return result;
        } catch (IOException | RuntimeException e) {
            String result = "The request could not be sent: " + e.getMessage();
            calls.add(new ToolCall(number, tool, arguments, at, false, null, result));
            return result;
        }
    }

    private static String limit(String body) {
        if (body == null) {
            return "";
        }
        return body.length() <= ANSWER_LIMIT ? body : body.substring(0, ANSWER_LIMIT) + "\n[cut at " + ANSWER_LIMIT
                + " characters]";
    }

    private static void put(Map<String, Object> arguments, String name, Object value) {
        if (value != null) {
            arguments.put(name, value);
        }
    }
}
