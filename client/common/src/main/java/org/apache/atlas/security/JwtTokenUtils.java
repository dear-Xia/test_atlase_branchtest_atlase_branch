package org.apache.atlas.security;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import sun.misc.BASE64Encoder;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;

public final class JwtTokenUtils {
    private static final ObjectMapper mapper = new ObjectMapper()
            .configure(DeserializationFeature.USE_BIG_DECIMAL_FOR_FLOATS, true);

    private String tokenUrl;
    private String userName;
    private String password;
    private String clientId;
    private String clientSecret;

    private String token;

    public JwtTokenUtils(String tokenUrl, String userName, String password, String clientId, String clientSecret) {
        this.tokenUrl = tokenUrl;
        this.userName = userName;
        this.password = password;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        ignoreSSLCert();
        refreshToken();
    }

    public String getToken() {
        return token;
    }

    public void refreshToken() {
        PrintWriter out = null;
        BufferedReader reader = null;
        HttpURLConnection conn = null;
        try {
            BASE64Encoder encoder = new BASE64Encoder();
            URL url = new URL(tokenUrl);
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-type", "application/x-www-form-urlencoded");
            conn.setRequestProperty("Accept", "*/*");
            conn.setRequestProperty("Authorization", String.format(
                    "Basic %s", encoder.encode(String.format("%s:%s", clientId,
                            clientSecret).getBytes("UTF-8"))));
            conn.setUseCaches(false);
            // 发送POST请求必须设置如下两行
            conn.setDoOutput(true);
            conn.setDoInput(true);

            // 获取URLConnection对象对应的输出流
            out = new PrintWriter(conn.getOutputStream());
            // 发送请求参数
            String params = "username=" + userName + "&password=" + password + "&grant_type=password";
            out.print(params);
            // flush输出流的缓冲
            out.flush();

            String line;
            reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            StringBuilder sb = new StringBuilder();
            while ((line = reader.readLine()) != null) {
                sb.append(line);
            }

            JsonNode jsonNode = mapper.readTree(sb.toString());
            token = jsonNode.get("access_token").asText();

        } catch (Exception ex) {
            throw new RuntimeException("Fetch token failed " + ex.getMessage());
        } finally {
            try {
                if (out != null) out.close();
                if (reader != null) reader.close();
                if (conn != null) conn.disconnect();
            } catch (Exception e) {
                // nothing need to do
            }
        }
    }

    private static void ignoreSSLCert() {
        try {
            TrustManager[] trustAllCerts = new TrustManager[]{new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() {
                    return null;
                }

                public void checkClientTrusted(X509Certificate[] certs, String authType) {
                    // do nothing
                }

                public void checkServerTrusted(X509Certificate[] certs, String authType) {
                    // do nothing
                }
            }};

            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

            // Install the all-trusting host verifier
            HttpsURLConnection.setDefaultHostnameVerifier((s, sslSession) -> trustAllHostVerifier());
            /* End of the fix*/
        } catch (KeyManagementException | NoSuchAlgorithmException ex) {
            // log it later
        }
    }

    private static boolean trustAllHostVerifier() {
        return true;
    }

}
