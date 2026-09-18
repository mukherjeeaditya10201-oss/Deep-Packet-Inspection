package com.dpi.rules;

import com.dpi.connection.Connection;
import com.dpi.parser.ParsedPacket;

import java.util.LinkedHashSet;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Holds the active block lists (IPs, domain keywords, and named apps
 * expanded into domain keywords) and decides what to do with each packet.
 *
 * The "postman" analogy from the original design: this is the part that
 * actually reads the envelope (headers) and, once known, the SNI, and
 * decides whether the letter gets delivered or thrown away.
 */
public final class RuleEngine {

    private final Set<String> blockedIps = new LinkedHashSet<>();
    private final Set<String> blockedDomainKeywords = new LinkedHashSet<>();
    private final Set<String> blockedAppNames = new LinkedHashSet<>();

    // Per-rule hit counters for the end-of-run summary.
    private final ConcurrentHashMap<String, AtomicLong> hitCounts = new ConcurrentHashMap<>();

    public void blockIp(String ip) {
        blockedIps.add(ip);
    }

    public void blockDomain(String domainKeyword) {
        blockedDomainKeywords.add(domainKeyword.toLowerCase());
    }

    public void blockApp(String appName) {
        blockedAppNames.add(appName);
        var keywords = AppSignatures.keywordsFor(appName);
        if (keywords.isEmpty()) {
            // Unknown app name: fall back to treating the name itself as a
            // domain keyword so --block-app still does something sensible.
            blockDomain(appName);
        } else {
            keywords.forEach(this::blockDomain);
        }
    }

    public boolean hasAnyRules() {
        return !blockedIps.isEmpty() || !blockedDomainKeywords.isEmpty();
    }

    /**
     * Decides the fate of one packet belonging to the given connection.
     * Called only from the single worker thread that owns this connection.
     */
    public Rule decide(Connection conn, ParsedPacket packet) {
        if (conn.isBlocked()) {
            count(conn.getBlockReason());
            return Rule.drop(conn.getBlockReason());
        }

        if (blockedIps.contains(packet.getSrcIp()) || blockedIps.contains(packet.getDstIp())) {
            String matchedIp = blockedIps.contains(packet.getDstIp()) ? packet.getDstIp() : packet.getSrcIp();
            String reason = "blocked-ip:" + matchedIp;
            conn.block(reason);
            count(reason);
            return Rule.drop(reason);
        }

        String sni = conn.getSni();
        if (sni != null) {
            for (String keyword : blockedDomainKeywords) {
                if (sni.toLowerCase().contains(keyword)) {
                    String reason = "blocked-domain:" + keyword;
                    conn.block(reason);
                    count(reason);
                    return Rule.drop(reason);
                }
            }
        }

        return Rule.forward();
    }

    private void count(String reason) {
        hitCounts.computeIfAbsent(reason, r -> new AtomicLong()).incrementAndGet();
    }

    public ConcurrentHashMap<String, AtomicLong> getHitCounts() {
        return hitCounts;
    }

    public Set<String> getBlockedIps() {
        return blockedIps;
    }

    public Set<String> getBlockedDomainKeywords() {
        return blockedDomainKeywords;
    }

    public Set<String> getBlockedAppNames() {
        return blockedAppNames;
    }
}
