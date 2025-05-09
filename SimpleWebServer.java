import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;
import java.util.Date;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HashMap;
import javax.net.ssl.HttpsURLConnection;
import java.security.KeyStore;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import com.sun.net.httpserver.HttpsServer;

public class SimpleWebServer {
    private static final Logger SECURITY_LOGGER = Logger.getLogger("SecurityLogger");

    // Security Headers Configuration
    private static final Map<String, String> SECURITY_HEADERS = Map.of(
        "Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload",
        "X-Content-Type-Options", "nosniff",
        "X-Frame-Options", "DENY",
        "X-XSS-Protection", "1; mode=block",
        "Referrer-Policy", "strict-origin-when-cross-origin",
        "Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'",
        "Permissions-Policy", "geolocation=(), camera=(), microphone=()"
    );
    private static final Pattern SUSPICIOUS_PATH_PATTERN = Pattern.compile("(/\\.\\.|%2e%2e|\\\\|\\/\\/|\\.\\/|\\.\\.\\/)");
    private static final Pattern SQL_INJECTION_PATTERN = Pattern.compile("('|\\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER)\\b)", Pattern.CASE_INSENSITIVE);
    private static final Pattern XSS_PATTERN = Pattern.compile("<script>|javascript:|onerror=", Pattern.CASE_INSENSITIVE);
    
    private static final int PORT = 8000;
    private static final int MAX_CONCURRENT_REQUESTS = 50;
    private static final long REQUEST_TIMEOUT_SECONDS = 10;
    private static final long MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB
    private static final Set<String> ALLOWED_EXTENSIONS = Set.of(
        ".html", ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico"
    );
    private static final ConcurrentHashMap<String, Integer> REQUEST_COUNTER = new ConcurrentHashMap<>();
    private static final int MAX_REQUESTS_PER_IP = 100; // Batasan request per IP

    // Konfigurasi Rate Limiting per Endpoint
    private static final Map<String, RateLimiter> ENDPOINT_RATE_LIMITERS = new ConcurrentHashMap<>() {{
        put("/login", new RateLimiter(10, TimeUnit.MINUTES)); // 10 request per menit
        put("/refresh", new RateLimiter(5, TimeUnit.MINUTES)); // 5 request per menit
        put("/", new RateLimiter(50, TimeUnit.MINUTES)); // 50 request per menit untuk file
    }};

    // Konfigurasi CSRF
    private static final String CSRF_TOKEN_HEADER = "X-CSRF-Token";
    private static final ConcurrentHashMap<String, String> CSRF_TOKENS = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<String, Boolean> TWO_FACTOR_ENABLED = new ConcurrentHashMap<>();
    private static final long CSRF_TOKEN_EXPIRATION = 1000 * 60 * 30; // 30 menit

    // Kelas Rate Limiter
    static class RateLimiter {
        private final int maxRequests;
        private final TimeUnit timeUnit;
        private final ConcurrentHashMap<String, AtomicInteger> requestCounts = new ConcurrentHashMap<>();
        private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);

        public RateLimiter(int maxRequests, TimeUnit timeUnit) {
            this.maxRequests = maxRequests;
            this.timeUnit = timeUnit;

            // Reset counter secara berkala
            scheduler.scheduleAtFixedRate(this::resetCounter, 0, 1, timeUnit);
        }

        private void resetCounter() {
            requestCounts.clear();
        }

        public boolean tryAcquire(String clientIp) {
            AtomicInteger count = requestCounts.computeIfAbsent(clientIp, k -> new AtomicInteger(0));
            return count.incrementAndGet() <= maxRequests;
        }
    }

    // Konfigurasi Autentikasi
    private static final HashMap<String, String> USERS = new HashMap<>();
    private static final int MAX_USERNAME_LENGTH = 50;
    private static final int MIN_PASSWORD_LENGTH = 8;
    private static final int MAX_PASSWORD_LENGTH = 100;

    // Konfigurasi JWT
    private static final String SECRET_KEY = getEnvOrDefault("JWT_SECRET_KEY", "TegarRestoSecretKey2023!@#");
    private static final String DEFAULT_USERNAME = getEnvOrDefault("APP_DEFAULT_USERNAME", "admin");
    private static final String DEFAULT_PASSWORD = getEnvOrDefault("APP_DEFAULT_PASSWORD", "admin123");
    private static final long ACCESS_TOKEN_EXPIRATION = 1000 * 60 * 30; // 30 menit
    private static final long REFRESH_TOKEN_EXPIRATION = 1000 * 60 * 60 * 24 * 7; // 7 hari
    private static final ConcurrentHashMap<String, String> REFRESH_TOKENS = new ConcurrentHashMap<>();

    public static void main(String[] args) throws Exception {
        // Inisialisasi pengguna
        initializeUsers();
        
        // Konfigurasi SSL/HTTPS
        HttpsServer httpsServer = HttpsServer.create(new InetSocketAddress(PORT), 0);
        SSLContext sslContext = configureSSLContext();
        
        SSLParameters sslParams = new SSLParameters();
        sslParams.setProtocols(new String[]{"TLSv1.2", "TLSv1.3"});
        sslParams.setCipherSuites(new String[]{
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", 
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
        });
        sslParams.setNeedClientAuth(false);
        sslParams.setWantClientAuth(false);

        httpsServer.setHttpsConfigurator(sslContext.createHttpsConfigurator(sslParams));
        
        // Executor dengan batasan thread
        httpsServer.setExecutor(Executors.newFixedThreadPool(MAX_CONCURRENT_REQUESTS, r -> {
            Thread t = new Thread(r);
            t.setDaemon(true);
            return t;
        }));

        httpsServer.createContext("/login", new LoginHandler());
        httpsServer.createContext("/refresh", new RefreshTokenHandler());
        httpsServer.createContext("/", new SecureFileHandler());
        httpsServer.start();
        
        // Pembersihan counter request secara berkala
        ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
        scheduler.scheduleAtFixedRate(REQUEST_COUNTER::clear, 1, 1, TimeUnit.HOURS);
        
        System.out.println("Secure server running on https://localhost:" + PORT);
    }

    private static boolean isRateLimitExceeded(String clientIP) {
        return REQUEST_COUNTER.merge(clientIP, 1, Integer::sum) > MAX_REQUESTS_PER_IP;
    }

    private static String getEnvOrDefault(String key, String defaultValue) {
        String value = System.getenv(key);
        return value != null && !value.isEmpty() ? value : defaultValue;
    }

    private static String generateCSRFToken(String username) {
        String token = UUID.randomUUID().toString();
        CSRF_TOKENS.put(username, token);
        return token;
    }

    private static boolean validateCSRFToken(String username, String token) {
        String storedToken = CSRF_TOKENS.get(username);
        return storedToken != null && storedToken.equals(token);
    }

    private static void cleanupExpiredCSRFTokens() {
        long currentTime = System.currentTimeMillis();
        CSRF_TOKENS.entrySet().removeIf(entry -> 
            currentTime - entry.getValue().hashCode() > CSRF_TOKEN_EXPIRATION
        );
    }

    private static void initializeUsers() {
        // Inisialisasi 2FA
        TWO_FACTOR_ENABLED.put(DEFAULT_USERNAME, false);
        String twoFactorSecret = TwoFactorAuthenticator.generateSecretKey();
        TwoFactorAuthenticator.registerUserSecret(DEFAULT_USERNAME, twoFactorSecret);
        
        // Simpan secret ke environment variable atau file konfigurasi
        System.setProperty("2FA_SECRET_" + DEFAULT_USERNAME, twoFactorSecret);
        // Gunakan environment variable atau default
        USERS.put(DEFAULT_USERNAME, hashPassword(DEFAULT_PASSWORD));
        USERS.put("user", hashPassword(getEnvOrDefault("APP_USER_PASSWORD", "user123")));
    }

    private static String hashPassword(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hashedBytes = md.digest(password.getBytes());
            return Base64.getEncoder().encodeToString(hashedBytes);
        } catch (NoSuchAlgorithmException e) {
            SECURITY_LOGGER.log(Level.SEVERE, "Password hashing failed", e);
            return null;
        }
    }

    private static final Logger SSL_LOGGER = Logger.getLogger("SSLLogger");

    private static Properties loadSSLProperties() {
        Properties props = new Properties();
        try (InputStream input = new FileInputStream("ssl_config.properties")) {
            props.load(input);
        } catch (IOException ex) {
            SSL_LOGGER.log(Level.SEVERE, "Gagal memuat konfigurasi SSL", ex);
        }
        return props;
    }

    private static SSLContext configureSSLContext() throws Exception {
        Properties sslProps = loadSSLProperties();

        // Muat konfigurasi SSL dari properties
        String keystorePath = sslProps.getProperty("ssl.keystore.path");
        String keystoreType = sslProps.getProperty("ssl.keystore.type", "PKCS12");
        String keystorePassword = System.getenv("SSL_KEYSTORE_PASSWORD");

        if (keystorePassword == null) {
            SSL_LOGGER.severe("SSL_KEYSTORE_PASSWORD tidak ditemukan. Gunakan environment variable.");
            throw new IllegalStateException("Keystore password tidak tersedia");
        }

        SSLContext sslContext = SSLContext.getInstance("TLS");
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        KeyStore keyStore = KeyStore.getInstance(keystoreType);

        try (FileInputStream fis = new FileInputStream(keystorePath)) {
            keyStore.load(fis, keystorePassword.toCharArray());
        }

        kmf.init(keyStore, keystorePassword.toCharArray());

        // Konfigurasi protokol dan cipher yang aman
        String[] protocols = sslProps.getProperty("ssl.protocols", "TLSv1.2,TLSv1.3").split(",");
        String[] ciphers = sslProps.getProperty("ssl.ciphers", 
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256").split(",");

        sslContext.init(kmf.getKeyManagers(), null, null);

        // Log informasi sertifikat
        logCertificateInfo(keyStore);

        return sslContext;
    }

    private static void logCertificateInfo(KeyStore keyStore) {
        try {
            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                Certificate cert = keyStore.getCertificate(alias);
                SSL_LOGGER.info("Certificate found: " + cert.getSubjectDN());
            }
        } catch (KeyStoreException e) {
            SSL_LOGGER.log(Level.SEVERE, "Gagal memuat informasi sertifikat", e);
        }
    }

    private static String generateAccessToken(String username) {
        long nowMillis = System.currentTimeMillis();
        Date now = new Date(nowMillis);
        Date expiration = new Date(nowMillis + ACCESS_TOKEN_EXPIRATION);

        return createToken(username, now, expiration, false);
    }

    private static String generateRefreshToken(String username) {
        long nowMillis = System.currentTimeMillis();
        Date now = new Date(nowMillis);
        Date expiration = new Date(nowMillis + REFRESH_TOKEN_EXPIRATION);

        String refreshToken = createToken(username, now, expiration, true);
        REFRESH_TOKENS.put(username, refreshToken);
        return refreshToken;
    }

    private static String createToken(String username, Date issuedAt, Date expiration, boolean isRefreshToken) {
        Key signingKey = new SecretKeySpec(SECRET_KEY.getBytes(), "HmacSHA256");

        return Base64.getEncoder().encodeToString((
            "{"+
            "\"sub\": \""+username+"\","+
            "\"iat\": "+issuedAt.getTime()+","+
            "\"exp\": "+expiration.getTime()+","+
            "\"type\": \""+((isRefreshToken) ? "refresh" : "access")+"\""+
            "}").getBytes());
    }

    private static String generateJwtToken(String username) {
        long nowMillis = System.currentTimeMillis();
        Date now = new Date(nowMillis);
        Date expiration = new Date(nowMillis + EXPIRATION_TIME);

        Key signingKey = new SecretKeySpec(SECRET_KEY.getBytes(), "HmacSHA256");

        return Base64.getEncoder().encodeToString((
            "{"+
            "\"sub\": \""+username+"\","+
            "\"iat\": "+nowMillis+","+
            "\"exp\": "+expiration.getTime()+
            "}").getBytes());
    }

    private static boolean validateJwtToken(String token, boolean checkRefreshToken) {
        try {
            byte[] decodedBytes = Base64.getDecoder().decode(token);
            String decodedToken = new String(decodedBytes);
            
            long currentTime = System.currentTimeMillis();
            long expirationTime = Long.parseLong(decodedToken.split("\"exp\": ")[1].split(",")[0]);
            String tokenType = decodedToken.split("\"type\": \"")[1].split("\"")[0];

            // Validasi tipe token
            if (checkRefreshToken && !"refresh".equals(tokenType)) {
                return false;
            }

            if (!checkRefreshToken && !"access".equals(tokenType)) {
                return false;
            }

            return currentTime < expirationTime;
        } catch (Exception e) {
            SECURITY_LOGGER.log(Level.WARNING, "JWT validation failed", e);
            return false;
        }
    }

    private static String refreshAccessToken(String refreshToken) {
        if (validateJwtToken(refreshToken, true)) {
            byte[] decodedBytes = Base64.getDecoder().decode(refreshToken);
            String decodedToken = new String(decodedBytes);
            String username = decodedToken.split("\"sub\": \"")[1].split("\"")[0];

            // Validasi refresh token yang tersimpan
            if (refreshToken.equals(REFRESH_TOKENS.get(username))) {
                return generateAccessToken(username);
            }
        }
        return null;
    }

    private static boolean validateJwtToken(String token) {
        try {
            byte[] decodedBytes = Base64.getDecoder().decode(token);
            String decodedToken = new String(decodedBytes);
            
            long currentTime = System.currentTimeMillis();
            long expirationTime = Long.parseLong(decodedToken.split("\"exp\": ")[1].split("}")[0]);

            return currentTime < expirationTime;
        } catch (Exception e) {
            SECURITY_LOGGER.log(Level.WARNING, "JWT validation failed", e);
            return false;
        }
    }

    private static boolean validateCredentials(String username, String password) {
        // Validasi panjang username dan password
        if (username == null || password == null ||
            username.length() > MAX_USERNAME_LENGTH ||
            password.length() < MIN_PASSWORD_LENGTH ||
            password.length() > MAX_PASSWORD_LENGTH) {
            return false;
        }

        String hashedPassword = hashPassword(password);
        return hashedPassword != null && hashedPassword.equals(USERS.get(username));
    }

    private static boolean isValidPath(String path) {
        // Cegah path traversal dan akses file berbahaya dengan validasi lebih ketat
        if (path == null || path.isEmpty()) return false;
        
        // Normalisasi path
        path = path.replaceAll("[/\\\\]+", "/");
        
        // Validasi karakter
        if (!path.matches("^[a-zA-Z0-9_/.-]+$")) return false;
        
        return path.startsWith("/") && 
               !path.contains("../") && 
               !path.contains("%") && 
               path.length() <= 255 && 
               !path.startsWith("/etc/") && 
               !path.startsWith("/root/");
    }

    private static boolean isAllowedFileType(String path) {
        return ALLOWED_EXTENSIONS.stream().anyMatch(path::endsWith);
    }

    private static void applySecurityHeaders(HttpExchange exchange) {
        // Terapkan security headers ke semua response
        for (Map.Entry<String, String> header : SECURITY_HEADERS.entrySet()) {
            exchange.getResponseHeaders().set(header.getKey(), header.getValue());
        }
    }

    private static void logSecurityEvent(String clientIP, String eventType, String details) {
        SECURITY_LOGGER.log(Level.WARNING, 
            "Security Event: {0} from IP {1}. Details: {2}", 
            new Object[]{eventType, clientIP, details}
        );
    }

    private static boolean isSecurePath(String path) {
        boolean isSecure = !SUSPICIOUS_PATH_PATTERN.matcher(path).find() &&
                           !SQL_INJECTION_PATTERN.matcher(path).find() &&
                           !XSS_PATTERN.matcher(path).find();
        
        if (!isSecure) {
            logSecurityEvent("UNKNOWN", "POTENTIAL_ATTACK", "Suspicious path detected: " + path);
        }
        
        return isSecure;
    }

    static class RefreshTokenHandler implements HttpHandler {
        private void checkRateLimit(HttpExchange exchange) throws IOException {
            String clientIp = exchange.getRemoteAddress().getAddress().getHostAddress();
            RateLimiter rateLimiter = ENDPOINT_RATE_LIMITERS.get("/refresh");

            if (rateLimiter == null || !rateLimiter.tryAcquire(clientIp)) {
                sendErrorResponse(exchange, 429, "Too Many Requests");
                return;
            }
        }

        private void validateCSRF(HttpExchange exchange, String username) throws IOException {
            String csrfToken = exchange.getRequestHeaders().getFirst(CSRF_TOKEN_HEADER);
            if (csrfToken == null || !validateCSRFToken(username, csrfToken)) {
                sendErrorResponse(exchange, 403, "Invalid CSRF Token");
                return;
            }
        }
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equals(exchange.getRequestMethod())) {
                sendErrorResponse(exchange, 405, "Method Not Allowed");
                return;
            }

            // Baca refresh token dari header
            String authHeader = exchange.getRequestHeaders().getFirst("Refresh-Token");
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                sendErrorResponse(exchange, 401, "Invalid or missing refresh token");
                return;
            }

            String refreshToken = authHeader.substring(7);

            // Ekstrak username dari refresh token
            byte[] decodedBytes = Base64.getDecoder().decode(refreshToken);
            String decodedToken = new String(decodedBytes);
            String username = decodedToken.split("\"sub\": \"")[1].split("\"")[0];

            // Validasi CSRF
            validateCSRF(exchange, username);

            String newAccessToken = refreshAccessToken(refreshToken);

            if (newAccessToken != null) {
                exchange.getResponseHeaders().set("Authorization", "Bearer " + newAccessToken);
                applySecurityHeaders(exchange);
                exchange.sendResponseHeaders(200, 0);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(("{ \"access_token\": \"" + newAccessToken + "\" }").getBytes());
                }
            } else {
                sendErrorResponse(exchange, 401, "Invalid refresh token");
            }
        }

        private void sendErrorResponse(HttpExchange exchange, int statusCode, String message) throws IOException {
            byte[] response = message.getBytes();
            exchange.sendResponseHeaders(statusCode, response.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(response);
            }
        }
    }

    static class LoginHandler implements HttpHandler {
        private boolean isTwoFactorRequired(String username) {
            return Boolean.TRUE.equals(TWO_FACTOR_ENABLED.get(username));
        }

        private void sendTwoFactorChallenge(HttpExchange exchange, String username, String accessToken) throws IOException {
            // Kirim challenge untuk 2FA
            exchange.getResponseHeaders().set("X-2FA-Required", "true");
            exchange.sendResponseHeaders(206, 0); // Partial Content
            
            try (OutputStream os = exchange.getResponseBody()) {
                String qrCodeUrl = TwoFactorAuthenticator.getQRCodeURL(username, 
                    System.getProperty("2FA_SECRET_" + username));
                
                String responseBody = String.format(
                    "{\"access_token\": \"%s\", \"qr_code_url\": \"%s\"}", 
                    accessToken, qrCodeUrl
                );
                os.write(responseBody.getBytes());
            }
        }
        private void checkRateLimit(HttpExchange exchange) throws IOException {
            String clientIp = exchange.getRemoteAddress().getAddress().getHostAddress();
            RateLimiter rateLimiter = ENDPOINT_RATE_LIMITERS.get("/login");

            if (rateLimiter == null || !rateLimiter.tryAcquire(clientIp)) {
                sendErrorResponse(exchange, 429, "Too Many Requests");
                return;
            }
        }
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equals(exchange.getRequestMethod())) {
                sendErrorResponse(exchange, 405, "Method Not Allowed");
                return;
            }

            // Baca input login
            String requestBody = new String(exchange.getRequestBody().readAllBytes());
            String[] credentials = requestBody.split("&");
            String username = credentials[0].split("=")[1];
            String password = credentials[1].split("=")[1];

            if (validateCredentials(username, password)) {
                // Login berhasil, generate token dan CSRF
                String accessToken = generateAccessToken(username);
                String refreshToken = generateRefreshToken(username);
                String csrfToken = generateCSRFToken(username);
                
                // Cek apakah 2FA diaktifkan
                if (isTwoFactorRequired(username)) {
                    sendTwoFactorChallenge(exchange, username, accessToken);
                    return;
                }
                
                // Kirim token dalam response
                exchange.getResponseHeaders().set("Authorization", "Bearer " + accessToken);
                exchange.getResponseHeaders().set("Refresh-Token", "Bearer " + refreshToken);
                exchange.getResponseHeaders().set(CSRF_TOKEN_HEADER, csrfToken);
                applySecurityHeaders(exchange);
                exchange.sendResponseHeaders(200, 0);
                
                try (OutputStream os = exchange.getResponseBody()) {
                    String responseBody = String.format(
                        "{\"access_token\": \"%s\", \"refresh_token\": \"%s\", \"csrf_token\": \"%s\"}", 
                        accessToken, refreshToken, csrfToken
                    );
                    os.write(responseBody.getBytes());
                }
            } else {
                // Login gagal
                sendErrorResponse(exchange, 401, "Unauthorized");
            }
        }

        private void sendErrorResponse(HttpExchange exchange, int statusCode, String message) throws IOException {
            byte[] response = message.getBytes();
            exchange.sendResponseHeaders(statusCode, response.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(response);
            }
        }
    }

    static class SecureFileHandler implements HttpHandler {
        private static final String AUTH_HEADER = "Authorization";

        private boolean isAuthenticated(HttpExchange exchange) {
            try {
                String authHeader = exchange.getRequestHeaders().getFirst(AUTH_HEADER);
                if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                    logSecurityEvent(exchange.getRemoteAddress().getAddress().getHostAddress(), "AUTH_FAIL", "Missing or invalid Authorization header");
                    return false;
                }

                String token = authHeader.substring(7);
                boolean isValid = validateJwtToken(token);

                if (!isValid) {
                    logSecurityEvent(exchange.getRemoteAddress().getAddress().getHostAddress(), "AUTH_FAIL", "Invalid or expired token");
                }

                return isValid;
            } catch (Exception e) {
                SECURITY_LOGGER.log(Level.WARNING, "Authentication check failed", e);
                return false;
            }
        }
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            // Cek autentikasi
            if (!isAuthenticated(exchange)) {
                sendErrorResponse(exchange, 401, "Unauthorized: Invalid or missing token");
                return;
            }

            String clientIP = exchange.getRemoteAddress().getAddress().getHostAddress();
            
            // Rate limiting
            if (isRateLimitExceeded(clientIP)) {
                logSecurityEvent(clientIP, "RATE_LIMIT", "Exceeded maximum requests");
                sendErrorResponse(exchange, 429, "Too Many Requests");
                return;
            }

            try {
                // Tambahkan header keamanan
                exchange.getResponseHeaders().add("X-Content-Type-Options", "nosniff");
                exchange.getResponseHeaders().add("X-Frame-Options", "DENY");
                exchange.getResponseHeaders().add("Content-Security-Policy", "default-src 'self'");
                exchange.getResponseHeaders().add("Strict-Transport-Security", "max-age=31536000; includeSubDomains");

                String path = exchange.getRequestURI().getPath();
                if (path.equals("/")) {
                    path = "/index.html";
                }

                // Validasi path
                if (!isValidPath(path) || !isSecurePath(path)) {
                    logSecurityEvent(clientIP, "PATH_VALIDATION_FAILED", "Invalid path: " + path);
                    sendErrorResponse(exchange, 403, "Forbidden");
                    return;
                }

                Path filePath = Paths.get("." + path);
                
                // Cek ekstensi file yang diizinkan
                if (!isAllowedFileType(path)) {
                    logSecurityEvent(clientIP, "FILE_TYPE_BLOCKED", "Blocked file type: " + path);
                    sendErrorResponse(exchange, 403, "File type not allowed");
                    return;
                }

                // Cek ukuran file
                long fileSize = Files.size(filePath);
                if (fileSize > MAX_FILE_SIZE) {
                    logSecurityEvent(clientIP, "FILE_SIZE_EXCEEDED", "File too large: " + path);
                    sendErrorResponse(exchange, 413, "File too large");
                    return;
                }

                byte[] response = Files.readAllBytes(filePath);
                String mimeType = getMimeType(path);
                exchange.getResponseHeaders().set("Content-Type", mimeType);
                exchange.sendResponseHeaders(200, response.length);
                
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(response);
                }
            } catch (IOException e) {
                logSecurityEvent(clientIP, "FILE_ACCESS_ERROR", "Error accessing file: " + e.getMessage());
                sendErrorResponse(exchange, 404, "File Not Found");
            }
        }

        private void sendErrorResponse(HttpExchange exchange, int statusCode, String message) throws IOException {
            byte[] response = message.getBytes();
            exchange.sendResponseHeaders(statusCode, response.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(response);
            }
        }

        private String getMimeType(String path) {
            if (path.endsWith(".html")) return "text/html";
            if (path.endsWith(".css")) return "text/css";
            if (path.endsWith(".js")) return "application/javascript";
            if (path.endsWith(".png")) return "image/png";
            if (path.endsWith(".jpg") || path.endsWith(".jpeg")) return "image/jpeg";
            if (path.endsWith(".gif")) return "image/gif";
            if (path.endsWith(".svg")) return "image/svg+xml";
            if (path.endsWith(".ico")) return "image/x-icon";
            return "application/octet-stream";
        }
    }
}