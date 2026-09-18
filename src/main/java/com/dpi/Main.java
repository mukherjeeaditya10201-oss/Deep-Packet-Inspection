package com.dpi;

import com.dpi.connection.Connection;
import com.dpi.engine.DpiEngine;
import com.dpi.rules.RuleEngine;
import com.dpi.stats.DpiStats;

import java.util.Locale;

/**
 * Deep Packet Inspection engine - command-line entry point.
 *
 * Usage:
 *   java -jar dpi-engine.jar <input.pcap> <output.pcap> [options]
 *
 * Options:
 *   --block-app NAME       Block a known app by name (e.g. YouTube, TikTok)
 *   --block-domain STRING  Block any TLS SNI containing this substring
 *   --block-ip IP          Block any packet to/from this IP address
 *   --threads N            Number of fast-path worker threads (default: CPU count)
 */
public final class Main {

    private Main() {
    }

    public static void main(String[] args) {
        if (args.length < 2) {
            printUsage();
            System.exit(1);
        }

        String inputPath = args[0];
        String outputPath = args[1];
        RuleEngine ruleEngine = new RuleEngine();
        int threads = Runtime.getRuntime().availableProcessors();

        for (int i = 2; i < args.length; i++) {
            String arg = args[i];
            switch (arg) {
                case "--block-app":
                    ruleEngine.blockApp(requireValue(args, ++i, "--block-app"));
                    break;
                case "--block-domain":
                    ruleEngine.blockDomain(requireValue(args, ++i, "--block-domain"));
                    break;
                case "--block-ip":
                    ruleEngine.blockIp(requireValue(args, ++i, "--block-ip"));
                    break;
                case "--threads":
                    threads = Integer.parseInt(requireValue(args, ++i, "--threads"));
                    break;
                default:
                    System.err.println("Unknown option: " + arg);
                    printUsage();
                    System.exit(1);
            }
        }

        System.out.println("Deep Packet Inspection Engine (Java)");
        System.out.println("  Input:   " + inputPath);
        System.out.println("  Output:  " + outputPath);
        System.out.println("  Workers: " + threads);
        if (!ruleEngine.getBlockedAppNames().isEmpty()) {
            System.out.println("  Blocked apps:    " + ruleEngine.getBlockedAppNames());
        }
        if (!ruleEngine.getBlockedDomainKeywords().isEmpty()) {
            System.out.println("  Blocked domains: " + ruleEngine.getBlockedDomainKeywords());
        }
        if (!ruleEngine.getBlockedIps().isEmpty()) {
            System.out.println("  Blocked IPs:     " + ruleEngine.getBlockedIps());
        }
        System.out.println();

        DpiEngine engine = new DpiEngine(inputPath, outputPath, ruleEngine, threads);
        long start = System.nanoTime();
        try {
            DpiStats stats = engine.run();
            long elapsedMs = (System.nanoTime() - start) / 1_000_000;
            printSummary(stats, engine, ruleEngine, elapsedMs);
        } catch (Exception e) {
            System.err.println("DPI engine failed: " + e.getMessage());
            System.exit(2);
        }
    }

    private static void printSummary(DpiStats stats, DpiEngine engine, RuleEngine ruleEngine, long elapsedMs) {
        long total = stats.getTotalPackets();
        long forwarded = stats.getForwardedPackets();
        long dropped = stats.getDroppedPackets();

        System.out.println("Run complete in " + elapsedMs + " ms");
        System.out.println("----------------------------------------");
        System.out.println("Total packets:      " + total);
        System.out.println("Forwarded packets:  " + forwarded + percentage(forwarded, total));
        System.out.println("Dropped packets:    " + dropped + percentage(dropped, total));
        System.out.println("Connections tracked: " + engine.getConnectionTable().size());

        long blockedConnections = engine.getConnectionTable().all().stream()
                .filter(Connection::isBlocked)
                .count();
        System.out.println("Connections blocked: " + blockedConnections);

        if (!ruleEngine.getHitCounts().isEmpty()) {
            System.out.println();
            System.out.println("Blocked by rule:");
            for (var entry : ruleEngine.getHitCounts().entrySet()) {
                System.out.println("  " + entry.getKey() + " -> " + entry.getValue().get() + " packets");
            }
        }
    }

    private static String percentage(long part, long whole) {
        if (whole == 0) {
            return "";
        }
        double pct = 100.0 * part / whole;
        return String.format(Locale.US, " (%.1f%%)", pct);
    }

    private static String requireValue(String[] args, int index, String option) {
        if (index >= args.length) {
            System.err.println("Missing value for " + option);
            printUsage();
            System.exit(1);
        }
        return args[index];
    }

    private static void printUsage() {
        System.out.println("Usage: java -jar dpi-engine.jar <input.pcap> <output.pcap> [options]");
        System.out.println("Options:");
        System.out.println("  --block-app NAME       Block a known app (YouTube, Netflix, TikTok, ...)");
        System.out.println("  --block-domain STRING  Block any TLS SNI containing this substring");
        System.out.println("  --block-ip IP          Block any packet to/from this IP address");
        System.out.println("  --threads N            Number of fast-path worker threads");
    }
}
