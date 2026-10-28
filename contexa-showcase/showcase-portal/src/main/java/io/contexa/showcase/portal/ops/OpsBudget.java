package io.contexa.showcase.portal.ops;

import io.contexa.showcase.portal.live.AgentRation;
import io.contexa.showcase.portal.live.LiveAllotment;
import io.contexa.showcase.portal.live.LiveRuns;
import io.contexa.showcase.portal.menu.AgentMenuStore;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * docs/agent Agent중심-화면 AC-9: the operator's budget, on the operator port only: the day's allotment and what was
 * spent, the day's share of live agent runs and the unit cost it rests on, the agent runs going now and their cap, the
 * state of the 80 percent alert, and what the agent menu's daily job spent. Every amount is the portal's own count from
 * the cost ledger by each model's price (AC-1); nothing here is estimated by this class.
 */
@Component
@ConditionalOnProperty(prefix = "showcase.portal.ops", name = "port")
public class OpsBudget {

    private final ObjectProvider<LiveRuns> live;
    private final ObjectProvider<LiveAllotment> allotment;
    private final ObjectProvider<AgentRation> ration;
    private final ObjectProvider<AgentMenuStore> menu;

    public OpsBudget(ObjectProvider<LiveRuns> live, ObjectProvider<LiveAllotment> allotment,
                     ObjectProvider<AgentRation> ration, ObjectProvider<AgentMenuStore> menu) {
        this.live = live;
        this.allotment = allotment;
        this.ration = ration;
        this.menu = menu;
    }

    /** The agent part of the live status; null while live runs are off. */
    public Map<String, Object> agent() {
        LiveRuns runs = live.getIfAvailable();
        LiveAllotment day = allotment.getIfAvailable();
        AgentRation share = ration.getIfAvailable();
        if (runs == null || day == null || share == null) {
            return null;
        }
        LiveAllotment.State state = day.state();
        Map<String, Object> agent = new LinkedHashMap<>();
        agent.put("agentRunsActive", runs.agentRunsActive());
        agent.put("agentConcurrent", runs.settings().agentConcurrent());
        agent.put("unitCostUsd", round(share.unitUsd()));
        agent.put("ticketsLeft", share.ticketsLeft());
        agent.put("remainingUsd", round(state.allotmentUsd() - state.spentUsd()));
        return agent;
    }

    /** The latest day of the agent menu's job; null before the job ever ran. */
    public AgentMenuStore.Job menuJob() {
        AgentMenuStore store = menu.getIfAvailable();
        List<AgentMenuStore.Job> jobs = store == null ? List.of() : store.jobs(1);
        return jobs.isEmpty() ? null : jobs.get(0);
    }

    /** The budget as one plain page for the operator. */
    public String page() {
        LiveAllotment day = allotment.getIfAvailable();
        Map<String, Object> agent = agent();
        StringBuilder html = new StringBuilder(2048);
        html.append("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">")
                .append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">")
                .append("<title>Showcase operator budget</title>")
                .append("<style>body{font:16px/1.5 system-ui,sans-serif;margin:2rem auto;max-width:44rem;padding:0 1rem}")
                .append("table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid #8884;padding:.4rem;")
                .append("text-align:left}h1{font-size:1.4rem}h2{font-size:1.1rem;margin-top:2rem}</style></head><body>")
                .append("<h1>Showcase operator budget</h1>");
        if (day == null || agent == null) {
            return html.append("<p>Live runs are off, so there is no allotment to show.</p></body></html>").toString();
        }
        LiveAllotment.State state = day.state();
        html.append("<h2>Today, ").append(state.day()).append(" (UTC)</h2><table>");
        row(html, "Daily allotment (USD)", plain(state.allotmentUsd()));
        row(html, "Spent today (USD)", plain(state.spentUsd()));
        row(html, "Remaining (USD)", plain((Double) agent.get("remainingUsd")));
        row(html, "80 percent alert", state.alerted() ? "raised" : "not raised");
        row(html, "Allotment", state.exhausted() ? "exhausted: live runs are refused" : "open");
        html.append("</table><h2>Live agent runs</h2><table>");
        row(html, "Agent unit cost (USD per run, average of the latest finished runs)", plain((Double) agent.get("unitCostUsd")));
        row(html, "Live agent runs the rest of the allotment pays for", agent.get("ticketsLeft"));
        row(html, "Agent runs going now / cap at once", agent.get("agentRunsActive") + " / " + agent.get("agentConcurrent"));
        html.append("</table><h2>Agent menu job (the latest day)</h2><table>");
        AgentMenuStore.Job job = menuJob();
        if (job == null) {
            html.append("<tr><td>The job has not run yet.</td></tr>");
        } else {
            row(html, "Day", job.day());
            row(html, "Ran / failed / skipped", job.ran() + " / " + job.failed() + " / " + job.skipped());
            row(html, "Spent (USD)", plain(job.spentUsd()));
            row(html, "Stopped", job.stopped() == null ? "ran through" : job.stopped());
        }
        return html.append("</table></body></html>").toString();
    }

    private static void row(StringBuilder html, String label, Object value) {
        html.append("<tr><th scope=\"row\">").append(escape(label)).append("</th><td>")
                .append(escape(String.valueOf(value))).append("</td></tr>");
    }

    private static String escape(String text) {
        return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }

    /** Dollars as a plain number with six decimals; a small amount never turns into "3.12E-4". */
    static String plain(double usd) {
        return String.format(Locale.ROOT, "%.6f", usd);
    }

    private static double round(double usd) {
        return Math.round(usd * 1_000_000d) / 1_000_000d;
    }
}
