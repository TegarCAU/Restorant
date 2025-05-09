import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

public class SecurityPenetrationTester {
    private static final Logger SECURITY_LOGGER = Logger.getLogger(SecurityPenetrationTester.class.getName());
    private static final int MAX_ATTEMPTS = 10;
    private static final String[] ATTACK_PAYLOADS = {
        "' OR 1=1 --",
        "<script>alert('XSS')</script>",
        "../../../etc/passwd",
        "javascript:alert('Vulnerability')",
        "' UNION SELECT username, password FROM users--"
    };

    private List<String> vulnerabilitiesFound = new ArrayList<>();

    public void runComprehensiveScan(String baseUrl) {
        SECURITY_LOGGER.info("🔍 Memulai Penetration Testing Komprehensif");
        
        testCSRFVulnerability(baseUrl);
        testSQLInjection(baseUrl);
        testXSSVulnerability(baseUrl);
        testRateLimitingBypassing(baseUrl);
        testAuthenticationBruteForce(baseUrl);

        reportVulnerabilities();
    }

    private void testCSRFVulnerability(String baseUrl) {
        try {
            HttpClient client = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_2)
                .connectTimeout(Duration.ofSeconds(10))
                .build();

            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/login"))
                .header("X-CSRF-Token", generateRandomToken())
                .POST(HttpRequest.BodyPublishers.noBody())
                .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 200) {
                vulnerabilitiesFound.add("Potensi Kerentanan CSRF Terdeteksi");
            }
        } catch (IOException | InterruptedException e) {
            SECURITY_LOGGER.log(Level.SEVERE, "Kesalahan dalam pengujian CSRF", e);
        }
    }

    private void testSQLInjection(String baseUrl) {
        HttpClient client = HttpClient.newBuilder()
            .version(HttpClient.Version.HTTP_2)
            .connectTimeout(Duration.ofSeconds(10))
            .build();

        for (String payload : ATTACK_PAYLOADS) {
            try {
                HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(baseUrl + "/login?username=" + payload))
                    .GET()
                    .build();

                HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

                if (response.statusCode() != 401 && response.statusCode() != 403) {
                    vulnerabilitiesFound.add("Potensi Kerentanan SQL Injection: " + payload);
                }
            } catch (IOException | InterruptedException e) {
                SECURITY_LOGGER.log(Level.SEVERE, "Kesalahan dalam pengujian SQL Injection", e);
            }
        }
    }

    private void testXSSVulnerability(String baseUrl) {
        HttpClient client = HttpClient.newBuilder()
            .version(HttpClient.Version.HTTP_2)
            .connectTimeout(Duration.ofSeconds(10))
            .build();

        for (String payload : ATTACK_PAYLOADS) {
            try {
                HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(baseUrl + "/menu?search=" + payload))
                    .GET()
                    .build();

                HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

                String contentType = response.headers().firstValue("Content-Type").orElse("");

                if (contentType.contains("text/html") && response.statusCode() == 200) {
                    vulnerabilitiesFound.add("Potensi Kerentanan XSS: " + payload);
                }
            } catch (IOException | InterruptedException e) {
                SECURITY_LOGGER.log(Level.SEVERE, "Kesalahan dalam pengujian XSS", e);
            }
        }
    }

    private void testRateLimitingBypassing(String baseUrl) {
        HttpClient client = HttpClient.newBuilder()
            .version(HttpClient.Version.HTTP_2)
            .connectTimeout(Duration.ofSeconds(10))
            .build();

        int successfulRequests = 0;
        for (int i = 0; i < MAX_ATTEMPTS * 2; i++) {
            try {
                HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(baseUrl + "/login"))
                    .POST(HttpRequest.BodyPublishers.noBody())
                    .build();

                HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
                
                if (response.statusCode() == 200) {
                    successfulRequests++;
                }
            } catch (IOException | InterruptedException e) {
                SECURITY_LOGGER.log(Level.SEVERE, "Kesalahan dalam pengujian Rate Limiting", e);
            }
        }

        if (successfulRequests > MAX_ATTEMPTS) {
            vulnerabilitiesFound.add("Potensi Bypass Rate Limiting Terdeteksi");
        }
    }

    private void testAuthenticationBruteForce(String baseUrl) {
        HttpClient client = HttpClient.newBuilder()
            .version(HttpClient.Version.HTTP_2)
            .connectTimeout(Duration.ofSeconds(10))
            .build();

        int successfulAttempts = 0;
        for (int i = 0; i < MAX_ATTEMPTS; i++) {
            try {
                String randomUsername = generateRandomToken();
                String randomPassword = generateRandomToken();

                HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(baseUrl + "/login"))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(String.format(
                        "{\"username\": \"%s\", \"password\": \"%s\"}", 
                        randomUsername, randomPassword
                    )))
                    .build();

                HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

                if (response.statusCode() == 200) {
                    successfulAttempts++;
                }
            } catch (IOException | InterruptedException e) {
                SECURITY_LOGGER.log(Level.SEVERE, "Kesalahan dalam pengujian Brute Force", e);
            }
        }

        if (successfulAttempts > MAX_ATTEMPTS / 2) {
            vulnerabilitiesFound.add("Potensi Kerentanan Brute Force Terdeteksi");
        }
    }

    private void reportVulnerabilities() {
        SECURITY_LOGGER.info("🚨 Laporan Vulnerabilitas Keamanan:");
        if (vulnerabilitiesFound.isEmpty()) {
            SECURITY_LOGGER.info("✅ Tidak ada kerentanan signifikan ditemukan.");
        } else {
            for (String vulnerability : vulnerabilitiesFound) {
                SECURITY_LOGGER.warning(vulnerability);
            }
        }
    }

    private String generateRandomToken() {
        byte[] randomBytes = new byte[16];
        new SecureRandom().nextBytes(randomBytes);
        return java.util.Base64.getEncoder().encodeToString(randomBytes);
    }

    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("Gunakan: java SecurityPenetrationTester <base_url>");
            System.exit(1);
        }

        SecurityPenetrationTester tester = new SecurityPenetrationTester();
        tester.runComprehensiveScan(args[0]);
    }
}
