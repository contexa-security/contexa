package io.contexa.showcase.portal.live;

import java.util.List;
import java.util.function.Supplier;

/**
 * docs/agent Agent중심-화면 AC-6: the day's share of live agent runs. What the day's allotment still holds, divided by
 * what an agent run costs on average, rounded down. The average is that of the latest finished runs of visitors (runs
 * the ledger has no cost for yet are left out); with fewer than {@link #MIN_RUNS} of them, the set price counts. A share
 * below one run means no agent run starts: the visitor is led to the stored runs, and a person's run is never rationed.
 */
public class AgentRation {

    /** How many of the latest finished visitor agent runs the unit cost is the average of. */
    public static final int RECENT_RUNS = 20;

    /** Fewest runs with a cost the average is trusted with; below it the set price counts. */
    public static final int MIN_RUNS = 5;

    /** What the latest finished agent runs of visitors cost, in dollars each, newest first. */
    @FunctionalInterface
    public interface Costs {
        List<Double> latest(int count);
    }

    private final Supplier<Double> remainingUsd;
    private final Costs costs;
    private final double defaultUnitUsd;

    /**
     * @param remainingUsd   what the day's allotment still holds, in dollars
     * @param defaultUnitUsd what an agent run is counted at while no finished run has a cost
     */
    public AgentRation(Supplier<Double> remainingUsd, Costs costs, double defaultUnitUsd) {
        this.remainingUsd = remainingUsd;
        this.costs = costs;
        this.defaultUnitUsd = defaultUnitUsd;
    }

    /** What an agent run costs on average, in dollars. */
    public double unitUsd() {
        double sum = 0d;
        int counted = 0;
        for (double cost : costs.latest(RECENT_RUNS)) {
            if (cost > 0d) {
                sum += cost;
                counted++;
            }
        }
        return counted < MIN_RUNS ? defaultUnitUsd : sum / counted;
    }

    /** How many more agent runs the day's allotment pays for. */
    public int ticketsLeft() {
        double remaining = remainingUsd.get();
        if (remaining <= 0d) {
            return 0;
        }
        return (int) Math.floor(remaining / unitUsd() + 1e-9);
    }

    public boolean hasTicket() {
        return ticketsLeft() >= 1;
    }
}
