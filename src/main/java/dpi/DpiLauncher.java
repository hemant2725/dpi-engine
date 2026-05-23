package dpi;

import org.springframework.boot.SpringApplication;

/**
 * Unified launcher. If the first two arguments are .pcap files, runs CLI mode.
 * Otherwise starts the Spring Boot API server.
 */
public class DpiLauncher {
    public static void main(String[] args) throws Exception {
        if (args.length >= 2 && args[0].endsWith(".pcap") && args[1].endsWith(".pcap")) {
            DpiEngine.main(args);
        } else {
            SpringApplication.run(DpiApiApplication.class, args);
        }
    }
}
