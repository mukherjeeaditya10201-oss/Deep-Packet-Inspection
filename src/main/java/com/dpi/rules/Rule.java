package com.dpi.rules;

/**
 * The verdict the rule engine reaches for a packet, plus a human-readable
 * reason (used both in the block reason recorded on the connection and in
 * the final per-rule hit-count summary).
 */
public final class Rule {

    public enum Verdict { FORWARD, DROP }

    private final Verdict verdict;
    private final String reason;

    private Rule(Verdict verdict, String reason) {
        this.verdict = verdict;
        this.reason = reason;
    }

    public static Rule forward() {
        return new Rule(Verdict.FORWARD, null);
    }

    public static Rule drop(String reason) {
        return new Rule(Verdict.DROP, reason);
    }

    public boolean isDrop() {
        return verdict == Verdict.DROP;
    }

    public String getReason() {
        return reason;
    }
}
