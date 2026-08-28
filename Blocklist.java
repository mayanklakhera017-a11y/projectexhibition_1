import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

/**
 * Holds blocking rules and decides whether a parsed packet should be
 * BLOCKED or FORWARDED.
 *
 * Matching strategy:
 *   1. SNI (domain) match       - only visible on the TLS ClientHello packet
 *   2. Static IP match          - blocklisted destination IPs
 *   3. Learned IP match         - once a domain is blocked via its SNI, its
 *                                  destination IP is remembered so that the
 *                                  REST of that flow (which carries no domain
 *                                  info, just encrypted TLS records) is also
 *                                  blocked. This mirrors how a real inline
 *                                  DPI/firewall enforces a domain block.
 *
 * Rules can be extended in code via addBlockedDomain()/addBlockedIp(), or by
 * dropping a "blocklist.txt" file next to the program (one entry per line,
 * '#' for comments). Lines that look like an IPv4 address are treated as IP
 * rules; everything else is treated as a domain rule.
 */
public class Blocklist {

    private final Set<String> blockedDomains = new HashSet<>();
    private final Set<String> blockedIps = new HashSet<>();
    private final Set<String> learnedBlockedIps = new HashSet<>();

    public Blocklist() {
        loadDefaults();
        loadFromFile("blocklist.txt");
    }

    private void loadDefaults() {
        // Sample starter rules - replace with whatever you want to demo
        // (ad/tracker domains here just so the tool blocks *something*
        // out of the box; swap in real threat-intel / malicious domains
        // for the exhibition if you want a more realistic demo).
        blockedDomains.add("doubleclick.net");
        blockedDomains.add("googlesyndication.com");
        blockedDomains.add("adservice.google.com");
    }

    private void loadFromFile(String path) {
        File f = new File(path);
        if (!f.exists()) return;

        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            String line;
            int loaded = 0;
            while ((line = br.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) continue;

                if (line.matches("\\d{1,3}(\\.\\d{1,3}){3}")) {
                    blockedIps.add(line);
                } else {
                    blockedDomains.add(line.toLowerCase());
                }
                loaded++;
            }
            if (loaded > 0) {
                System.out.println("Loaded " + loaded + " rule(s) from blocklist.txt");
            }
        } catch (IOException e) {
            System.err.println("Warning: could not read blocklist.txt: " + e.getMessage());
        }
    }

    public void addBlockedDomain(String domain) {
        blockedDomains.add(domain.toLowerCase());
    }

    public void addBlockedIp(String ip) {
        blockedIps.add(ip);
    }

    /** Exact match or subdomain match (blocking "doubleclick.net" also blocks "ads.doubleclick.net"). */
    private boolean domainMatches(String hostname) {
        String lower = hostname.toLowerCase();
        for (String blocked : blockedDomains) {
            if (lower.equals(blocked) || lower.endsWith("." + blocked)) {
                return true;
            }
        }
        return false;
    }

    public BlockDecision evaluate(PacketTypes.ParsedPacket packet) {
        String dstIp = packet.getTuple().getDstIp();

        if (packet.getSni().isPresent()) {
            String domain = packet.getSni().get();
            if (domainMatches(domain)) {
                learnedBlockedIps.add(dstIp);
                return new BlockDecision(true, "SNI match: " + domain);
            }
        }

        if (blockedIps.contains(dstIp)) {
            return new BlockDecision(true, "Blocklisted IP: " + dstIp);
        }

        if (learnedBlockedIps.contains(dstIp)) {
            return new BlockDecision(true, "Flow to previously blocked domain (" + dstIp + ")");
        }

        return new BlockDecision(false, null);
    }

    public static class BlockDecision {
        public final boolean blocked;
        public final String reason;

        public BlockDecision(boolean blocked, String reason) {
            this.blocked = blocked;
            this.reason = reason;
        }
    }
}
