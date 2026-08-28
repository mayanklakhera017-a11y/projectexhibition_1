import java.io.File;
import java.io.IOException;     
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.Set;


public class Main {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        String pcapFile = selectPcapFile(scanner);

        if (pcapFile == null || pcapFile.trim().isEmpty()) {
            System.out.println("No valid PCAP file selected. Exiting.");
            return;
        }
         System.out.println("     ");
        System.out.println("        PACKET ANALYZER - DPI ENGINE             ");
        System.out.println("      ");
        System.out.println("Processing file: " + pcapFile + "\n");

  long startTime = System.currentTimeMillis();


        int totalPackets = 0;
        int parsedPackets = 0;
        int sniCount = 0;
        int forwardedPackets = 0;
        int blockedPackets = 0;

        Map<PacketTypes.Protocol, Integer> protocolCounts = new HashMap<>();
        Set<String> accessedWebsites = new HashSet<>();
        Set<String> blockedWebsites = new HashSet<>();
        Blocklist blocklist = new Blocklist();

try (PcapReader reader = new PcapReader(pcapFile)) {
            byte[] packetBytes;

            while ((packetBytes = reader.readNextPacket()) != null) {
                totalPackets++;
                var parsedOpt = PacketParser.parseEthernet(packetBytes);

                if (parsedOpt.isPresent()) {
                    parsedPackets++;
                    var packet = parsedOpt.get();
                    PacketTypes.Protocol proto = packet.getTuple().getProtocol();

                    // Track Protocol Tally
                    protocolCounts.put(proto, protocolCounts.getOrDefault(proto, 0) + 1);

                    System.out.printf("Packet #%d: %s\n", totalPackets, packet.getTuple());

                    if (packet.getSni().isPresent()) {
                        sniCount++;
                        String domain = packet.getSni().get();
                        accessedWebsites.add(domain);
                        System.out.println("  └── Extracted SNI: " + domain);
                    }

                    // DPI blocking decision
                    Blocklist.BlockDecision decision = blocklist.evaluate(packet);
                    if (decision.blocked) {
                        blockedPackets++;
                        if (packet.getSni().isPresent()) {
                            blockedWebsites.add(packet.getSni().get());
                        }
                        System.out.println("  └── Action: BLOCKED (" + decision.reason + ")");
                    } else {
                        forwardedPackets++;
                    }
                }
            }

            long duration = System.currentTimeMillis() - startTime;
        
         System.out.println("    ");
            System.out.println("             EXECUTION SUMMARY REPORT             ");
            System.out.println("         ");
            System.out.printf("  Total Packets Captured : %d\n", totalPackets);
            System.out.printf("  Successfully Parsed    : %d\n", parsedPackets);
            System.out.printf("  SNI Records Identified : %d\n", sniCount);
            System.out.println("--------------------------------------------------");
            System.out.println("  Action Metrics:");
            System.out.printf("    • Forwarded Packets  : %d\n", forwardedPackets);
            System.out.printf("    • Blocked Packets    : %d\n", blockedPackets);
            System.out.println("--------------------------------------------------");
            System.out.println("  Protocol Breakdown:");
            for (Map.Entry<PacketTypes.Protocol, Integer> entry : protocolCounts.entrySet()) {
                double percentage = (entry.getValue() * 100.0) / parsedPackets;
                System.out.printf("    • %-8s : %d (%.1f%%)\n", entry.getKey(), entry.getValue(), percentage);
            }System.out.println("");
            System.out.println("  Accessed Websites / Domains Identified:");
            if (accessedWebsites.isEmpty()) {
                System.out.println("    • No TLS SNI domains detected.");
            } else {
                for (String domain : accessedWebsites) {
                    String tag = blockedWebsites.contains(domain) ? " [BLOCKED]" : " [ALLOWED]";
                    System.out.println("    • " + domain + tag);
                }
            }
            System.out.println("      ");
            System.out.printf("  Processing Time       : %d ms\n", duration);
            System.out.println("\n");

        } catch (IOException e) {
            System.err.println("Error reading PCAP file: " + e.getMessage());
        }
    }

    private static String selectPcapFile(Scanner scanner) {
        File currentDir = new File(".");
        File[] files = currentDir.listFiles((dir, name) -> name.toLowerCase().endsWith(".pcap"));

        List<File> pcapFiles = new ArrayList<>();
        if (files != null) {
            for(File file : files) {
                pcapFiles.add(file);
            }
        }

        System.out.println("      ");
        System.out.println("               SELECT A PCAP FILE                 ");
        System.out.println("      ");

        if (pcapFiles.isEmpty()) {
            System.out.println("No .pcap files found in current directory.");
            System.out.print("Please enter file name or path manually: ");
            return scanner.nextLine().trim();
        }

        for (int i = 0; i < pcapFiles.size(); i++) {
            System.out.printf(" [%d] %s\n", i + 1, pcapFiles.get(i).getName());
        }
        System.out.printf(" [%d] Enter custom filename or full path\n", pcapFiles.size() + 1);

        System.out.print("\nSelect an option (1-" + (pcapFiles.size() + 1) + "): ");
        String input = scanner.nextLine().trim();

        try {
            int choice = Integer.parseInt(input);
            if (choice >= 1 && choice <= pcapFiles.size()) {
                return pcapFiles.get(choice - 1).getPath();
            } else if (choice == pcapFiles.size() + 1) {
                System.out.print("Enter custom PCAP filename or path: ");
                return scanner.nextLine().trim();
            } else {
                System.out.println("Invalid selection. Defaulting to custom prompt.");
            }
        } catch (NumberFormatException e) {
            
            if (new File(input).exists()) {
                return input;
            }
        }

        System.out.print("Enter PCAP file path: ");
        return scanner.nextLine().trim();
    }
}