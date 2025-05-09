import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class TwoFactorAuthenticator {
    private static final int TIME_STEP_SECONDS = 30;
    private static final int CODE_DIGITS = 6;
    private static final Map<String, String> USER_2FA_SECRETS = new HashMap<>();

    // Generate secret key untuk 2FA
    public static String generateSecretKey() {
        byte[] buffer = new byte[20];
        new SecureRandom().nextBytes(buffer);
        return Base64.getEncoder().encodeToString(buffer);
    }

    // Simpan secret key untuk pengguna
    public static void registerUserSecret(String username, String secret) {
        USER_2FA_SECRETS.put(username, secret);
    }

    // Validasi kode TOTP
    public static boolean validateTOTPCode(String username, String userProvidedCode) {
        String secretKey = USER_2FA_SECRETS.get(username);
        if (secretKey == null) {
            return false;
        }

        long currentTimeSeconds = System.currentTimeMillis() / 1000L;
        
        // Validasi kode untuk waktu saat ini dan 2 interval sebelumnya
        for (int i = -1; i <= 1; i++) {
            long timeStep = (currentTimeSeconds / TIME_STEP_SECONDS) + i;
            String generatedCode = generateTOTPCode(secretKey, timeStep);
            
            if (generatedCode.equals(userProvidedCode)) {
                return true;
            }
        }
        
        return false;
    }

    // Generate kode TOTP
    private static String generateTOTPCode(String secretKey, long timeStep) {
        try {
            byte[] secretBytes = Base64.getDecoder().decode(secretKey);
            byte[] timeStepBytes = new byte[8];
            
            for (int i = 7; i >= 0; i--) {
                timeStepBytes[i] = (byte) (timeStep & 0xFF);
                timeStep >>= 8;
            }

            Mac hmac = Mac.getInstance("HmacSHA1");
            SecretKeySpec secretKeySpec = new SecretKeySpec(secretBytes, "RAW");
            hmac.init(secretKeySpec);
            byte[] hmacResult = hmac.doFinal(timeStepBytes);

            // Offset dinamis
            int offset = hmacResult[hmacResult.length - 1] & 0xf;
            int code = 
                ((hmacResult[offset] & 0x7f) << 24) |
                ((hmacResult[offset + 1] & 0xff) << 16) |
                ((hmacResult[offset + 2] & 0xff) << 8) |
                (hmacResult[offset + 3] & 0xff);

            // Ambil 6 digit terakhir
            code %= (int) Math.pow(10, CODE_DIGITS);
            return String.format("%0" + CODE_DIGITS + "d", code);
        } catch (Exception e) {
            return null;
        }
    }

    // Generate URL untuk QR Code (kompatibel Google Authenticator)
    public static String getQRCodeURL(String username, String secretKey) {
        String issuer = "TegarResto";
        return String.format(
            "otpauth://totp/%s:%s?secret=%s&issuer=%s", 
            issuer, username, secretKey, issuer
        );
    }
}
