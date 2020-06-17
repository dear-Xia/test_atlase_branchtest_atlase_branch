
/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.atlas.web.filters;

import com.google.common.annotations.VisibleForTesting;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import org.apache.atlas.ApplicationProperties;
import org.apache.atlas.web.security.AtlasAuthenticationProvider;
import org.apache.commons.configuration.Configuration;
import org.apache.commons.lang.StringUtils;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;

import javax.inject.Inject;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.*;
import java.text.ParseException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Only support oauth2 authorization code flow
 */

@Component("rayfaySSOAuthenticationFilter")
public class AtlasRayfaySSOAuthenticationFilter implements Filter {
    private static final Logger LOG = LoggerFactory.getLogger(AtlasRayfaySSOAuthenticationFilter.class);

    public static final String BROWSER_USERAGENT = "atlas.sso.rayfay.browser.useragent";
    public static final String JWT_AUTH_PROVIDER_URL = "atlas.sso.rayfay.providerurl";
    public static final String JWT_ORIGINAL_URL_QUERY_PARAM = "atlas.sso.rayfay.query.param.originalurl";
    public static final String JWT_ORIGINAL_URL_QUERY_PARAM_DEFAULT = "originalUrl";
    public static final String DEFAULT_BROWSER_USERAGENT = "Mozilla,Opera,Chrome";
    public static final String PROXY_ATLAS_URL_PATH = "/atlas";
    public static final String JWT_RAYFAY_SSO_APPID = "atlas.sso.rayfay.appid";
    public static final String JWT_RAYFAY_SSO_APPSECRET = "atlas.sso.rayray.appsecret";

    private final AtlasAuthenticationProvider authenticationProvider;

    private SSOAuthenticationProperties jwtProperties;

    private String originalUrlQueryParam = "originalUrl";
    private String authenticationProviderUrl = null;
    private RSAPublicKey publicKey = null;
    private String cookieName = "hadoop-jwt";
    private Configuration configuration = null;
    private boolean ssoEnabled = false;
    private JWSVerifier verifier = null;
    private String appId = null;
    private String appSecret = null;
    @VisibleForTesting
    private final int MAX_LOGIN_URL_LENGTH = 2043;

    @Inject
    public AtlasRayfaySSOAuthenticationFilter(AtlasAuthenticationProvider authenticationProvider) {
        this.authenticationProvider = authenticationProvider;
        try {
            configuration = ApplicationProperties.get();
        } catch (Exception e) {
            LOG.error("Error while getting application properties", e);
        }
        if (configuration != null) {
            ssoEnabled = configuration.getBoolean("atlas.sso.rayfay.enabled", false);
            jwtProperties = loadJwtProperties();
        }
        setJwtProperties();
    }

    public AtlasRayfaySSOAuthenticationFilter(AtlasAuthenticationProvider authenticationProvider,
                                              SSOAuthenticationProperties jwtProperties) {
        this.authenticationProvider = authenticationProvider;
        this.jwtProperties = jwtProperties;
        setJwtProperties();
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
    }

    /*
     * doFilter of AtlasRayfaySSOAuthenticationFilter is the first in the filter list so in this it check for the request
     * if the request is from browser and sso is enabled then it process the request against rayfay sso
     * else if it's ssoenable and the request is with local login string then it show's the appropriate msg
     * else if ssoenable is false then it contiunes with further filters as it was before sso
     */
    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {

        HttpServletResponse httpResponse = (HttpServletResponse) servletResponse;

        AtlasResponseRequestWrapper responseWrapper = new AtlasResponseRequestWrapper(httpResponse);
        responseWrapper.setHeader("X-Frame-Options", "DENY");
        responseWrapper.setHeader("X-Content-Type-Options", "nosniff");
        responseWrapper.setHeader("X-XSS-Protection", "1; mode=block");
        responseWrapper.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");


        HttpServletRequest httpRequest = (HttpServletRequest) servletRequest;

        //handle logout for SSO
        String requestURI = httpRequest.getRequestURI();
        if("/logout".equalsIgnoreCase(requestURI)) {
            if(ssoEnabled) {
                httpResponse.sendRedirect(buildLogoutURL(httpRequest));
            } else {
                httpResponse.sendRedirect("/logout.html");
            }
            return;
        }

        if (!ssoEnabled) {
            filterChain.doFilter(servletRequest, servletResponse);
            return;
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Rayfay SSO doFilter {}", httpRequest.getRequestURI());
        }

        if (httpRequest.getSession() != null && httpRequest.getSession().getAttribute("locallogin") != null) {
            servletRequest.setAttribute("ssoEnabled", false);
            filterChain.doFilter(servletRequest, servletResponse);
            return;
        }



        if (jwtProperties == null || isAuthenticated()) {
            filterChain.doFilter(servletRequest, servletResponse);
            return;
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Rayfay ssoEnabled  {} {}", ssoEnabled, httpRequest.getRequestURI());
        }

        HttpServletResponse httpServletResponse = (HttpServletResponse) servletResponse;

        //handle jwt token in header for rest api
        String serializedJWT = getJWTFromHeader(httpRequest);
        boolean jwtFromHeader = true;
        if(StringUtils.isEmpty(serializedJWT)) {
            String code = httpRequest.getParameter("code");
            if(code != null && StringUtils.isNotEmpty(code)) {
                serializedJWT = challengeToken(httpRequest, code);
                jwtFromHeader = false;
            } else {
                redirectToRayfaySSO(httpRequest, httpServletResponse, filterChain);
                return;
            }
        }

        if (serializedJWT != null) {
            SignedJWT jwtToken = null;
            try {
                jwtToken = SignedJWT.parse(serializedJWT);
                boolean valid = validateToken(jwtToken);
                //if the public key provide is correct and also token is not expired the process token
                if (valid) {
                    String userName = jwtToken.getJWTClaimsSet().getStringClaim("user_name");
                    LOG.info("SSO login user : {} ", userName);
                    //if we get the userName from the token then log into atlas using the same user
                    if (userName != null && !userName.trim().isEmpty()) {
                        String[] groups = jwtToken.getJWTClaimsSet().getStringArrayClaim("seeAlso");
                        List<GrantedAuthority> grantedAuths = Arrays.stream(groups).map(g -> new SimpleGrantedAuthority(g)).collect(Collectors.toList());
                        final UserDetails principal = new User(userName, "", grantedAuths);
                        final Authentication finalAuthentication = new UsernamePasswordAuthenticationToken(principal, "", grantedAuths);
                        WebAuthenticationDetails webDetails = new WebAuthenticationDetails(httpRequest);
                        ((AbstractAuthenticationToken) finalAuthentication).setDetails(webDetails);
                        authenticationProvider.setSsoEnabled(ssoEnabled);
                        Authentication authentication = authenticationProvider.authenticate(finalAuthentication);
                        SecurityContextHolder.getContext().setAuthentication(authentication);
                    }

                    if(jwtFromHeader) {
                        filterChain.doFilter(servletRequest, httpServletResponse);
                    } else {
                        httpResponse.sendRedirect(getRedirectURL(httpRequest));
                    }
                } else {  // if the token is not valid then redirect to knox sso
                    redirectToRayfaySSO(httpRequest, httpServletResponse, filterChain);
                }
            } catch (ParseException e) {
                LOG.warn("Unable to parse the JWT token", e);
                redirectToRayfaySSO(httpRequest, httpServletResponse, filterChain);
            }
        } else {
            redirectToRayfaySSO(httpRequest, httpServletResponse, filterChain);
        }
    }

    public boolean isEnable() {
        return ssoEnabled;
    }

    public String buildLogoutURL(HttpServletRequest request) {
        StringBuilder logoutURL = new StringBuilder(authenticationProviderUrl);
        logoutURL.append("/logout?redirect=");
        String originalURL = request.getRequestURL().toString();
        String requestURI = request.getRequestURI();
        originalURL = originalURL.replace(requestURI,"");
        logoutURL.append(originalURL).append("/logout.html");
        return logoutURL.toString();
    }

    private void redirectToRayfaySSO(HttpServletRequest httpRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws IOException, ServletException {

        if (!isWebUserAgent(httpRequest.getHeader("User-Agent"))) {
            filterChain.doFilter(httpRequest, httpServletResponse);
            return;
        }

        String ajaxRequestHeader = httpRequest.getHeader("X-Requested-With");

        if ("XMLHttpRequest".equals(ajaxRequestHeader)) {
            String ssourl = constructLoginURL(httpRequest, true);
            JSONObject json = new JSONObject();
            json.put("rayfayssoredirectURL", URLEncoder.encode(ssourl, "UTF-8"));
            httpServletResponse.setContentType("application/json");
            httpServletResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            httpServletResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, json.toString());

        } else {
            String ssourl = constructLoginURL(httpRequest, false);
            httpServletResponse.sendRedirect(ssourl);
        }

    }

    private boolean isWebUserAgent(String userAgent) {
        boolean isWeb = false;
        if (jwtProperties != null) {
            String userAgentList[] = jwtProperties.getUserAgentList();
            if (userAgentList != null && userAgentList.length > 0) {
                for (String ua : userAgentList) {
                    if (StringUtils.startsWithIgnoreCase(userAgent, ua)) {
                        isWeb = true;
                        break;
                    }
                }
            }
        }
        return isWeb;
    }


    private void setJwtProperties() {
        if (jwtProperties != null) {
            authenticationProviderUrl = jwtProperties.getAuthenticationProviderUrl();
            publicKey = jwtProperties.getPublicKey();
            cookieName = jwtProperties.getCookieName();
            originalUrlQueryParam = jwtProperties.getOriginalUrlQueryParam();
            appId = jwtProperties.getAppId();
            appSecret = jwtProperties.getAppSecret();
            if (publicKey != null) {
                verifier = new RSASSAVerifier(publicKey);
            }
        }
    }

    /**
     * Do not try to validate JWT if user already authenticated via other
     * provider
     *
     * @return true, if JWT validation required
     */
    private boolean isAuthenticated() {
        Authentication existingAuth = SecurityContextHolder.getContext().getAuthentication();
        return !(!(existingAuth != null && existingAuth.isAuthenticated()) || existingAuth instanceof SSOAuthentication);
    }

    /**
     * JWT TOken from http request header
     *  Authorization:Bearer AFSE628DFSFSFSF
     * @param req
     * @return
     */
    private String getJWTFromHeader(HttpServletRequest req) {
        String authorizationHeader = req.getHeader("Authorization");
        if(authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            return null;
        }

        return authorizationHeader.substring("Bearer ".length());
    }

    /**
     * Create the URL to be used for authentication of the user in the absence
     * of a JWT token within the incoming request.
     *
     * @param request for getting the original request URL
     * @return url to use as login url for redirect ,like http://rfuaa.k8s.rf.io/oauth/authorize?client_id=idmsys&redirect_uri=http://rfidm.k8s.rf.io/login&response_type=code&state=2cnksQ
     */
    protected String constructLoginURL(HttpServletRequest request, boolean isXMLRequest) {
        StringBuilder rayfayLoginURL = new StringBuilder();

        rayfayLoginURL
                .append(authenticationProviderUrl)
                .append("/oauth/authorize?client_id=")
                .append(appId)
                .append("&redirect_uri=")
                .append(getRedirectURL(request))
                .append("&response_type=code");

        return rayfayLoginURL.toString();
    }

    private String getRedirectURL(HttpServletRequest request) {
        String originalQueryString = request.getQueryString();
        String code = request.getParameter("code");
        if(code != null && StringUtils.isNotEmpty(code)) {
            String codeNVPair = "code=" + code;
            originalQueryString = originalQueryString
                    .replace("&" + codeNVPair, "")
                    .replace(codeNVPair,"");
        }
        String originalURL = request.getRequestURL().toString();
        return (originalQueryString == null || StringUtils.isEmpty(originalQueryString)) ? originalURL : originalURL + "?" + originalQueryString;
    }

    /**
     * This method provides a single method for validating the JWT for use in
     * request processing. It provides for the override of specific aspects of
     * this implementation through submethods used within but also allows for
     * the override of the entire token validation algorithm.
     *
     * @param jwtToken the token to validate
     * @return true if valid
     */
    protected boolean validateToken(SignedJWT jwtToken) {
        boolean isValid = validateSignature(jwtToken);

        if (isValid) {
            isValid = validateExpiration(jwtToken);
            if (!isValid) {
                LOG.warn("Expiration time validation of JWT token failed.");
            }
        } else {
            LOG.warn("Signature of JWT token could not be verified. Please check the public key");
        }
        return isValid;
    }

    /**
     * Verify the signature of the JWT token in this method. This method depends
     * on the public key that was established during init based upon the
     * provisioned public key. Override this method in subclasses in order to
     * customize the signature verification behavior.
     *
     * @param jwtToken the token that contains the signature to be validated
     * @return valid true if signature verifies successfully; false otherwise
     */
    protected boolean validateSignature(SignedJWT jwtToken) {
        boolean valid = false;
        if (JWSObject.State.SIGNED == jwtToken.getState()) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("SSO token is in a SIGNED state");
            }
            if (jwtToken.getSignature() != null) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("SSO token signature is not null");
                }
                try {
                    if (verifier != null && jwtToken.verify(verifier)) {
                        valid = true;
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("SSO token has been successfully verified");
                        }
                    } else {
                        LOG.warn("SSO signature verification failed.Please check the public key");
                    }
                } catch (JOSEException je) {
                    LOG.warn("Error while validating signature", je);
                } catch (Exception e) {
                    LOG.warn("Error while validating signature", e);
                }
            }
        }
        return valid;
    }

    /**
     * Validate that the expiration time of the JWT token has not been violated.
     * If it has then throw an AuthenticationException. Override this method in
     * subclasses in order to customize the expiration validation behavior.
     *
     * @param jwtToken the token that contains the expiration date to validate
     * @return valid true if the token has not expired; false otherwise
     */
    protected boolean validateExpiration(SignedJWT jwtToken) {
        boolean valid = false;
        try {
            Date expires = jwtToken.getJWTClaimsSet().getExpirationTime();
            if (expires == null || new Date().before(expires)) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("SSO token expiration date has been successfully validated");
                }
                valid = true;
            } else {
                LOG.warn("SSO expiration date validation failed.");
            }
        } catch (ParseException pe) {
            LOG.warn("SSO expiration date validation failed.", pe);
        }
        return valid;
    }

    @Override
    public void destroy() {
    }

    public SSOAuthenticationProperties loadJwtProperties() {
        String providerUrl = configuration.getString(JWT_AUTH_PROVIDER_URL);
        if (providerUrl != null && configuration.getBoolean("atlas.sso.rayfay.enabled", false)) {
            SSOAuthenticationProperties jwtProperties = new SSOAuthenticationProperties();
            ignoreSSLCert();
            String publicKeyPathStr = retrievePublicKey(providerUrl);
            if (publicKeyPathStr == null) {
                LOG.error("Public key pem not retrieved for SSO auth provider {}. SSO auth will be disabled", providerUrl);
                return null;
            }
            jwtProperties.setAuthenticationProviderUrl(providerUrl);
            jwtProperties.setOriginalUrlQueryParam(configuration.getString(JWT_ORIGINAL_URL_QUERY_PARAM, JWT_ORIGINAL_URL_QUERY_PARAM_DEFAULT));
            String[] userAgent = configuration.getStringArray(BROWSER_USERAGENT);
            if (userAgent != null && userAgent.length > 0) {
                jwtProperties.setUserAgentList(userAgent);
            } else {
                jwtProperties.setUserAgentList(DEFAULT_BROWSER_USERAGENT.split(","));
            }
            try {
                RSAPublicKey publicKey = parseRSAPublicKey(publicKeyPathStr);
                jwtProperties.setPublicKey(publicKey);
            } catch (IOException e) {
                LOG.error("Unable to read public certificate file. JWT auth will be disabled.", e);
            } catch (CertificateException e) {
                LOG.error("Unable to parse public certificate file. JWT auth will be disabled.", e);
            } catch (ServletException e) {
                LOG.error("ServletException while processing the properties", e);
            }
            jwtProperties.setAppId(configuration.getString(JWT_RAYFAY_SSO_APPID));
            jwtProperties.setAppSecret(configuration.getString(JWT_RAYFAY_SSO_APPSECRET));
            return jwtProperties;
        } else {
            return null;
        }
    }

    private String challengeToken(HttpServletRequest request, String code) {
        int retry = 0;
        long s0 = System.currentTimeMillis();
        LOG.info("Connecting to fetch access token");
        while (retry++ < 3) {
            try {
                String token = _challengeToken(request, code);
                long cost = System.currentTimeMillis() - s0;
                LOG.info("Connected to fetch access token success cost: {}", cost);
                return token;
            } catch (RuntimeException ex) {
                if (retry == 3) {
                    long cost = System.currentTimeMillis() - s0;
                    LOG.info("Connecting to fetch access token {} times failed {} cost: {}", retry, ex.getMessage(), cost);
                    return null;
                }
                LOG.info("Connecting to fetch access token {} times", retry);
            }
        }
        return null;
    }

    private String _challengeToken(HttpServletRequest request, String code) {
        String tokenURL = authenticationProviderUrl + "/oauth/token";
        String token;
        try {
            URL url = new URL(tokenURL);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setDoOutput(true);
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Authorization", " Basic " + Base64.getEncoder().encodeToString((appId + ":" + appSecret).getBytes()));
            conn.setRequestProperty("Content-type", "application/x-www-form-urlencoded");
            conn.setRequestProperty("Accept", "*/*");
            DataOutputStream writer = new DataOutputStream(conn.getOutputStream());

            writer.writeBytes("code="+ code + "&grant_type=authorization_code&redirect_uri=" + getRedirectURL(request));
            writer.flush();
            String line;
            BufferedReader reader = new BufferedReader(new
                    InputStreamReader(conn.getInputStream()));
            StringBuilder sb = new StringBuilder();
            while ((line = reader.readLine()) != null) {
                sb.append(line);
            }

            String responseString = sb.toString();
            JSONObject json_data = (JSONObject) new JSONParser().parse(responseString);

            token = (String) json_data.get("access_token");
            writer.close();
            reader.close();
            conn.disconnect();
        } catch (Exception ex) {
            throw new RuntimeException("Fetch token failed " + ex.getMessage());
        }
        return token;
    }

    private String retrievePublicKey(String providerUrl) {
        int retry = 0;
        long s0 = System.currentTimeMillis();
        LOG.info("Connecting to fetch SSO Server Public Key");
        while (retry++ < 3) {
            try {
                String token = _retrievePublicKey(providerUrl);
                long cost = System.currentTimeMillis() - s0;
                LOG.info("Connected to fetch SSO Server Public Key success cost: {}", cost);
                return token;
            } catch (RuntimeException ex) {
                if (retry == 3) {
                    long cost = System.currentTimeMillis() - s0;
                    LOG.info("Connecting to fetch SSO Server Public Key {} times failed {} cost: {}", retry, ex.getMessage(), cost);
                    return null;
                }
                LOG.info("Connecting to fetch SSO Server Public Key {} times", retry);
            }
        }
        return null;
    }

    private String _retrievePublicKey(String providerUrl) {
        String tokenURL = providerUrl + "/oauth/token_key";
        String publicKey;
        try {
            URL url = new URL(tokenURL);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setDoOutput(true);
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Accept", "*/*");

            String line;
            BufferedReader reader = new BufferedReader(new
                    InputStreamReader(conn.getInputStream()));
            StringBuilder sb = new StringBuilder();
            while ((line = reader.readLine()) != null) {
                sb.append(line);
            }

            String responseString = sb.toString();
            JSONObject json_data = (JSONObject) new JSONParser().parse(responseString);

            publicKey = (String) json_data.get("value");

            reader.close();
            conn.disconnect();
        } catch (Exception ex) {
            throw new RuntimeException("Fetch public key failed " + ex.getMessage());
        }
        return publicKey;
    }

    public static RSAPublicKey parseRSAPublicKey(String pem)
            throws CertificateException, UnsupportedEncodingException,
            ServletException {
        return RsaKeyHelper.parsePublicKey(pem);
    }

    public static void ignoreSSLCert() {
        try {
            TrustManager[] trustAllCerts = new TrustManager[]{new X509TrustManager() {
                public java.security.cert.X509Certificate[] getAcceptedIssuers() {
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
            HttpsURLConnection.setDefaultHostnameVerifier((s, sslSession)->trustAllHostVerifier());
            /* End of the fix*/
        } catch (KeyManagementException | NoSuchAlgorithmException ex) {
            LOG.error("Exception: ", ex);
        }
    }

    private static boolean trustAllHostVerifier() {
        return true;
    }

    static class RsaKeyHelper {
        private static final Pattern SSH_PUB_KEY = Pattern.compile("ssh-(rsa|dsa) ([A-Za-z0-9/+]+=*) (.*)");
        private static String BEGIN = "-----BEGIN";
        private static Pattern PEM_DATA = Pattern.compile("-----BEGIN (.*)-----(.*)-----END (.*)-----", Pattern.DOTALL);
        private static Charset UTF8 = Charset.forName("UTF-8");

        static KeyPair parseKeyPair(String pemData) {
            Matcher m = PEM_DATA.matcher(pemData.trim());

            if (!m.matches()) {
                throw new IllegalArgumentException("String is not PEM encoded data");
            }

            String type = m.group(1);
            final byte[] content = b64Decode(utf8Encode(m.group(2)));

            PublicKey publicKey;
            PrivateKey privateKey = null;

            try {
                KeyFactory fact = KeyFactory.getInstance("RSA");
                if (type.equals("PUBLIC KEY")) {
                    KeySpec keySpec = new X509EncodedKeySpec(content);
                    publicKey = fact.generatePublic(keySpec);
                } else {
                    throw new IllegalArgumentException(type + " is not a supported format");
                }

                return new KeyPair(publicKey, privateKey);
            }
            catch (InvalidKeySpecException e) {
                throw new RuntimeException(e);
            }
            catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException(e);
            }
        }


        private static RSAPublicKey parsePublicKey(String key) throws CertificateException, UnsupportedEncodingException, ServletException {
            Matcher m = SSH_PUB_KEY.matcher(key);

            if (m.matches()) {
                String alg = m.group(1);
                String encKey = m.group(2);
                //String id = m.group(3);

                if (!"rsa".equalsIgnoreCase(alg)) {
                    throw new IllegalArgumentException("Only RSA is currently supported, but algorithm was " + alg);
                }

                return parseSSHPublicKey(encKey);
            } else if (!key.startsWith(BEGIN)) {
                // Assume it's the plain Base64 encoded ssh key without the "ssh-rsa" at the start
                return parseSSHPublicKey(key);
            }

            KeyPair kp = parseKeyPair(key);

            if (kp.getPublic() == null) {
                throw new IllegalArgumentException("Key data does not contain a public key");
            }

            return (RSAPublicKey) kp.getPublic();
        }

        private static RSAPublicKey parseSSHPublicKey(String encKey) {
            final byte[] PREFIX = new byte[]{0, 0, 0, 7, 's', 's', 'h', '-', 'r', 's', 'a'};
            ByteArrayInputStream in = new ByteArrayInputStream(b64Decode(utf8Encode(encKey)));

            byte[] prefix = new byte[11];

            try {
                if (in.read(prefix) != 11 || !Arrays.equals(PREFIX, prefix)) {
                    throw new IllegalArgumentException("SSH key prefix not found");
                }

                BigInteger e = new BigInteger(readBigInteger(in));
                BigInteger n = new BigInteger(readBigInteger(in));

                return createPublicKey(n, e);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        static RSAPublicKey createPublicKey(BigInteger n, BigInteger e) {
            try {
                return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(n, e));
            } catch (Exception ex) {
                throw new RuntimeException(ex);
            }
        }

        private static byte[] readBigInteger(ByteArrayInputStream in) throws IOException {
            byte[] b = new byte[4];

            if (in.read(b) != 4) {
                throw new IOException("Expected length data as 4 bytes");
            }

            int l = (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3];

            b = new byte[l];

            if (in.read(b) != l) {
                throw new IOException("Expected " + l + " key bytes");
            }

            return b;
        }

        private static byte[] b64Decode(byte[] bytes) {
            return Base64Codec.decode(bytes);
        }

        private static byte[] utf8Encode(CharSequence string) {
            try {
                ByteBuffer bytes = UTF8.newEncoder().encode(CharBuffer.wrap(string));
                byte[] bytesCopy = new byte[bytes.limit()];
                System.arraycopy(bytes.array(), 0, bytesCopy, 0, bytes.limit());
                return bytesCopy;
            } catch (CharacterCodingException e) {
                throw new RuntimeException(e);
            }
        }
    }

    static class Base64Codec {

        /** No options specified. Value is zero. */
        public final static int NO_OPTIONS = 0;

        /** Specify encoding in first bit. Value is one. */
        public final static int ENCODE = 1;


        /** Specify decoding in first bit. Value is zero. */
        public final static int DECODE = 0;

        /** Do break lines when encoding. Value is 8. */
        public final static int DO_BREAK_LINES = 8;

        /**
         * Encode using Base64-like encoding that is URL- and Filename-safe as described
         * in Section 4 of RFC3548:
         * <a href="http://www.faqs.org/rfcs/rfc3548.html">http://www.faqs.org/rfcs/rfc3548.html</a>.
         * It is important to note that data encoded this way is <em>not</em> officially valid Base64,
         * or at the very least should not be called Base64 without also specifying that is
         * was encoded using the URL- and Filename-safe dialect.
         */
        public final static int URL_SAFE = 16;


        /**
         * Encode using the special "ordered" dialect of Base64 described here:
         * <a href="http://www.faqs.org/qa/rfcc-1940.html">http://www.faqs.org/qa/rfcc-1940.html</a>.
         */
        public final static int ORDERED = 32;


        /** Maximum line length (76) of Base64 output. */
        private final static int MAX_LINE_LENGTH = 76;


        /** The equals sign (=) as a byte. */
        private final static byte EQUALS_SIGN = (byte)'=';


        /** The new line character (\n) as a byte. */
        private final static byte NEW_LINE = (byte)'\n';

        private final static byte WHITE_SPACE_ENC = -5; // Indicates white space in encoding
        private final static byte EQUALS_SIGN_ENC = -1; // Indicates equals sign in encoding


        /* ********  S T A N D A R D   B A S E 6 4   A L P H A B E T  ******** */

        /** The 64 valid Base64 values. */
        /* Host platform me be something funny like EBCDIC, so we hardcode these values. */
        private final static byte[] _STANDARD_ALPHABET = {
                (byte)'A', (byte)'B', (byte)'C', (byte)'D', (byte)'E', (byte)'F', (byte)'G',
                (byte)'H', (byte)'I', (byte)'J', (byte)'K', (byte)'L', (byte)'M', (byte)'N',
                (byte)'O', (byte)'P', (byte)'Q', (byte)'R', (byte)'S', (byte)'T', (byte)'U',
                (byte)'V', (byte)'W', (byte)'X', (byte)'Y', (byte)'Z',
                (byte)'a', (byte)'b', (byte)'c', (byte)'d', (byte)'e', (byte)'f', (byte)'g',
                (byte)'h', (byte)'i', (byte)'j', (byte)'k', (byte)'l', (byte)'m', (byte)'n',
                (byte)'o', (byte)'p', (byte)'q', (byte)'r', (byte)'s', (byte)'t', (byte)'u',
                (byte)'v', (byte)'w', (byte)'x', (byte)'y', (byte)'z',
                (byte)'0', (byte)'1', (byte)'2', (byte)'3', (byte)'4', (byte)'5',
                (byte)'6', (byte)'7', (byte)'8', (byte)'9', (byte)'+', (byte)'/'
        };


        /**
         * Translates a Base64 value to either its 6-bit reconstruction value
         * or a negative number indicating some other meaning.
         **/
        private final static byte[] _STANDARD_DECODABET = {
                -9,-9,-9,-9,-9,-9,-9,-9,-9,                 // Decimal  0 -  8
                -5,-5,                                      // Whitespace: Tab and Linefeed
                -9,-9,                                      // Decimal 11 - 12
                -5,                                         // Whitespace: Carriage Return
                -9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,     // Decimal 14 - 26
                -9,-9,-9,-9,-9,                             // Decimal 27 - 31
                -5,                                         // Whitespace: Space
                -9,-9,-9,-9,-9,-9,-9,-9,-9,-9,              // Decimal 33 - 42
                62,                                         // Plus sign at decimal 43
                -9,-9,-9,                                   // Decimal 44 - 46
                63,                                         // Slash at decimal 47
                52,53,54,55,56,57,58,59,60,61,              // Numbers zero through nine
                -9,-9,-9,                                   // Decimal 58 - 60
                -1,                                         // Equals sign at decimal 61
                -9,-9,-9,                                      // Decimal 62 - 64
                0,1,2,3,4,5,6,7,8,9,10,11,12,13,            // Letters 'A' through 'N'
                14,15,16,17,18,19,20,21,22,23,24,25,        // Letters 'O' through 'Z'
                -9,-9,-9,-9,-9,-9,                          // Decimal 91 - 96
                26,27,28,29,30,31,32,33,34,35,36,37,38,     // Letters 'a' through 'm'
                39,40,41,42,43,44,45,46,47,48,49,50,51,     // Letters 'n' through 'z'
                -9,-9,-9,-9,-9                              // Decimal 123 - 127
                ,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,       // Decimal 128 - 139
                -9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,     // Decimal 140 - 152
                -9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,     // Decimal 153 - 165
                -9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,     // Decimal 166 - 178
                -9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,     // Decimal 179 - 191
                -9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,     // Decimal 192 - 204
                -9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,     // Decimal 205 - 217
                -9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,     // Decimal 218 - 230
                -9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,     // Decimal 231 - 243
                -9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9         // Decimal 244 - 255
        };


        /* ********  U R L   S A F E   B A S E 6 4   A L P H A B E T  ******** */

        /**
         * Used in the URL- and Filename-safe dialect described in Section 4 of RFC3548:
         * <a href="http://www.faqs.org/rfcs/rfc3548.html">http://www.faqs.org/rfcs/rfc3548.html</a>.
         * Notice that the last two bytes become "hyphen" and "underscore" instead of "plus" and "slash."
         */
        private final static byte[] _URL_SAFE_ALPHABET = {
                (byte)'A', (byte)'B', (byte)'C', (byte)'D', (byte)'E', (byte)'F', (byte)'G',
                (byte)'H', (byte)'I', (byte)'J', (byte)'K', (byte)'L', (byte)'M', (byte)'N',
                (byte)'O', (byte)'P', (byte)'Q', (byte)'R', (byte)'S', (byte)'T', (byte)'U',
                (byte)'V', (byte)'W', (byte)'X', (byte)'Y', (byte)'Z',
                (byte)'a', (byte)'b', (byte)'c', (byte)'d', (byte)'e', (byte)'f', (byte)'g',
                (byte)'h', (byte)'i', (byte)'j', (byte)'k', (byte)'l', (byte)'m', (byte)'n',
                (byte)'o', (byte)'p', (byte)'q', (byte)'r', (byte)'s', (byte)'t', (byte)'u',
                (byte)'v', (byte)'w', (byte)'x', (byte)'y', (byte)'z',
                (byte)'0', (byte)'1', (byte)'2', (byte)'3', (byte)'4', (byte)'5',
                (byte)'6', (byte)'7', (byte)'8', (byte)'9', (byte)'-', (byte)'_'
        };

        /**
         * Used in decoding URL- and Filename-safe dialects of Base64.
         */
        private final static byte[] _URL_SAFE_DECODABET = {
                -9,-9,-9,-9,-9,-9,-9,-9,-9,                 // Decimal  0 -  8
                -5,-5,                                      // Whitespace: Tab and Linefeed
                -9,-9,                                      // Decimal 11 - 12
                -5,                                         // Whitespace: Carriage Return
                -9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,     // Decimal 14 - 26
                -9,-9,-9,-9,-9,                             // Decimal 27 - 31
                -5,                                         // Whitespace: Space
                -9,-9,-9,-9,-9,-9,-9,-9,-9,-9,              // Decimal 33 - 42
                -9,                                         // Plus sign at decimal 43
                -9,                                         // Decimal 44
                62,                                         // Minus sign at decimal 45
                -9,                                         // Decimal 46
                -9,                                         // Slash at decimal 47
                52,53,54,55,56,57,58,59,60,61,              // Numbers zero through nine
                -9,-9,-9,                                   // Decimal 58 - 60
                -1,                                         // Equals sign at decimal 61
                -9,-9,-9,                                   // Decimal 62 - 64
                0,1,2,3,4,5,6,7,8,9,10,11,12,13,            // Letters 'A' through 'N'
                14,15,16,17,18,19,20,21,22,23,24,25,        // Letters 'O' through 'Z'
                -9,-9,-9,-9,                                // Decimal 91 - 94
                63,                                         // Underscore at decimal 95
                -9,                                         // Decimal 96
                26,27,28,29,30,31,32,33,34,35,36,37,38,     // Letters 'a' through 'm'
                39,40,41,42,43,44,45,46,47,48,49,50,51,     // Letters 'n' through 'z'
                -9,-9,-9,-9,-9                              // Decimal 123 - 127
                ,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,     // Decimal 128 - 139
                -9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,     // Decimal 140 - 152
                -9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,     // Decimal 153 - 165
                -9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,     // Decimal 166 - 178
                -9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,     // Decimal 179 - 191
                -9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,     // Decimal 192 - 204
                -9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,     // Decimal 205 - 217
                -9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,     // Decimal 218 - 230
                -9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,     // Decimal 231 - 243
                -9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9         // Decimal 244 - 255
        };



        /* ********  O R D E R E D   B A S E 6 4   A L P H A B E T  ******** */

        /**
         * I don't get the point of this technique, but someone requested it,
         * and it is described here:
         * <a href="http://www.faqs.org/qa/rfcc-1940.html">http://www.faqs.org/qa/rfcc-1940.html</a>.
         */
        private final static byte[] _ORDERED_ALPHABET = {
                (byte)'-',
                (byte)'0', (byte)'1', (byte)'2', (byte)'3', (byte)'4',
                (byte)'5', (byte)'6', (byte)'7', (byte)'8', (byte)'9',
                (byte)'A', (byte)'B', (byte)'C', (byte)'D', (byte)'E', (byte)'F', (byte)'G',
                (byte)'H', (byte)'I', (byte)'J', (byte)'K', (byte)'L', (byte)'M', (byte)'N',
                (byte)'O', (byte)'P', (byte)'Q', (byte)'R', (byte)'S', (byte)'T', (byte)'U',
                (byte)'V', (byte)'W', (byte)'X', (byte)'Y', (byte)'Z',
                (byte)'_',
                (byte)'a', (byte)'b', (byte)'c', (byte)'d', (byte)'e', (byte)'f', (byte)'g',
                (byte)'h', (byte)'i', (byte)'j', (byte)'k', (byte)'l', (byte)'m', (byte)'n',
                (byte)'o', (byte)'p', (byte)'q', (byte)'r', (byte)'s', (byte)'t', (byte)'u',
                (byte)'v', (byte)'w', (byte)'x', (byte)'y', (byte)'z'
        };

        /**
         * Used in decoding the "ordered" dialect of Base64.
         */
        private final static byte[] _ORDERED_DECODABET = {
                -9,-9,-9,-9,-9,-9,-9,-9,-9,                 // Decimal  0 -  8
                -5,-5,                                      // Whitespace: Tab and Linefeed
                -9,-9,                                      // Decimal 11 - 12
                -5,                                         // Whitespace: Carriage Return
                -9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,     // Decimal 14 - 26
                -9,-9,-9,-9,-9,                             // Decimal 27 - 31
                -5,                                         // Whitespace: Space
                -9,-9,-9,-9,-9,-9,-9,-9,-9,-9,              // Decimal 33 - 42
                -9,                                         // Plus sign at decimal 43
                -9,                                         // Decimal 44
                0,                                          // Minus sign at decimal 45
                -9,                                         // Decimal 46
                -9,                                         // Slash at decimal 47
                1,2,3,4,5,6,7,8,9,10,                       // Numbers zero through nine
                -9,-9,-9,                                   // Decimal 58 - 60
                -1,                                         // Equals sign at decimal 61
                -9,-9,-9,                                   // Decimal 62 - 64
                11,12,13,14,15,16,17,18,19,20,21,22,23,     // Letters 'A' through 'M'
                24,25,26,27,28,29,30,31,32,33,34,35,36,     // Letters 'N' through 'Z'
                -9,-9,-9,-9,                                // Decimal 91 - 94
                37,                                         // Underscore at decimal 95
                -9,                                         // Decimal 96
                38,39,40,41,42,43,44,45,46,47,48,49,50,     // Letters 'a' through 'm'
                51,52,53,54,55,56,57,58,59,60,61,62,63,     // Letters 'n' through 'z'
                -9,-9,-9,-9,-9                                 // Decimal 123 - 127
                ,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,     // Decimal 128 - 139
                -9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,     // Decimal 140 - 152
                -9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,     // Decimal 153 - 165
                -9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,     // Decimal 166 - 178
                -9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,     // Decimal 179 - 191
                -9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,     // Decimal 192 - 204
                -9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,     // Decimal 205 - 217
                -9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,     // Decimal 218 - 230
                -9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,     // Decimal 231 - 243
                -9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9,-9         // Decimal 244 - 255
        };


        public static byte[] decode(byte[] bytes) {
            return decode(bytes, 0, bytes.length, NO_OPTIONS);
        }

        public static byte[] encode(byte[] bytes) {
            return encodeBytesToBytes(bytes, 0, bytes.length, NO_OPTIONS);
        }

        public static boolean isBase64(byte[] bytes) {
            try {
                decode(bytes);
            } catch (InvalidBase64CharacterException e) {
                return false;
            }
            return true;
        }

        /**
         * Returns one of the _SOMETHING_ALPHABET byte arrays depending on
         * the options specified.
         * It's possible, though silly, to specify ORDERED <b>and</b> URLSAFE
         * in which case one of them will be picked, though there is
         * no guarantee as to which one will be picked.
         */
        private static byte[] getAlphabet( int options ) {
            if ((options & URL_SAFE) == URL_SAFE) {
                return _URL_SAFE_ALPHABET;
            } else if ((options & ORDERED) == ORDERED) {
                return _ORDERED_ALPHABET;
            } else {
                return _STANDARD_ALPHABET;
            }
        }

        /**
         * Returns one of the _SOMETHING_DECODABET byte arrays depending on
         * the options specified.
         * It's possible, though silly, to specify ORDERED and URL_SAFE
         * in which case one of them will be picked, though there is
         * no guarantee as to which one will be picked.
         */
        private static byte[] getDecodabet( int options ) {
            if( (options & URL_SAFE) == URL_SAFE) {
                return _URL_SAFE_DECODABET;
            } else if ((options & ORDERED) == ORDERED) {
                return _ORDERED_DECODABET;
            } else {
                return _STANDARD_DECODABET;
            }
        }


        /* ********  E N C O D I N G   M E T H O D S  ******** */

        /**
         * <p>Encodes up to three bytes of the array <var>source</var>
         * and writes the resulting four Base64 bytes to <var>destination</var>.
         * The source and destination arrays can be manipulated
         * anywhere along their length by specifying
         * <var>srcOffset</var> and <var>destOffset</var>.
         * This method does not check to make sure your arrays
         * are large enough to accomodate <var>srcOffset</var> + 3 for
         * the <var>source</var> array or <var>destOffset</var> + 4 for
         * the <var>destination</var> array.
         * The actual number of significant bytes in your array is
         * given by <var>numSigBytes</var>.</p>
         * <p>This is the lowest level of the encoding methods with
         * all possible parameters.</p>
         *
         * @param source the array to convert
         * @param srcOffset the index where conversion begins
         * @param numSigBytes the number of significant bytes in your array
         * @param destination the array to hold the conversion
         * @param destOffset the index where output will be put
         * @return the <var>destination</var> array
         * @since 1.3
         */
        private static byte[] encode3to4(
                byte[] source, int srcOffset, int numSigBytes,
                byte[] destination, int destOffset, int options ) {

            byte[] ALPHABET = getAlphabet( options );

            //           1         2         3
            // 01234567890123456789012345678901 Bit position
            // --------000000001111111122222222 Array position from threeBytes
            // --------|    ||    ||    ||    | Six bit groups to index ALPHABET
            //          >>18  >>12  >> 6  >> 0  Right shift necessary
            //                0x3f  0x3f  0x3f  Additional AND

            // Create buffer with zero-padding if there are only one or two
            // significant bytes passed in the array.
            // We have to shift left 24 in order to flush out the 1's that appear
            // when Java treats a value as negative that is cast from a byte to an int.
            int inBuff =   ( numSigBytes > 0 ? ((source[ srcOffset     ] << 24) >>>  8) : 0 )
                    | ( numSigBytes > 1 ? ((source[ srcOffset + 1 ] << 24) >>> 16) : 0 )
                    | ( numSigBytes > 2 ? ((source[ srcOffset + 2 ] << 24) >>> 24) : 0 );

            switch( numSigBytes )
            {
                case 3:
                    destination[ destOffset     ] = ALPHABET[ (inBuff >>> 18)        ];
                    destination[ destOffset + 1 ] = ALPHABET[ (inBuff >>> 12) & 0x3f ];
                    destination[ destOffset + 2 ] = ALPHABET[ (inBuff >>>  6) & 0x3f ];
                    destination[ destOffset + 3 ] = ALPHABET[ (inBuff       ) & 0x3f ];
                    return destination;

                case 2:
                    destination[ destOffset     ] = ALPHABET[ (inBuff >>> 18)        ];
                    destination[ destOffset + 1 ] = ALPHABET[ (inBuff >>> 12) & 0x3f ];
                    destination[ destOffset + 2 ] = ALPHABET[ (inBuff >>>  6) & 0x3f ];
                    destination[ destOffset + 3 ] = EQUALS_SIGN;
                    return destination;

                case 1:
                    destination[ destOffset     ] = ALPHABET[ (inBuff >>> 18)        ];
                    destination[ destOffset + 1 ] = ALPHABET[ (inBuff >>> 12) & 0x3f ];
                    destination[ destOffset + 2 ] = EQUALS_SIGN;
                    destination[ destOffset + 3 ] = EQUALS_SIGN;
                    return destination;

                default:
                    return destination;
            }
        }


        /**
         *
         * @param source The data to convert
         * @param off Offset in array where conversion should begin
         * @param len Length of data to convert
         * @param options Specified options
         * @return The Base64-encoded data as a String
         * @see Base64Codec#DO_BREAK_LINES
         * @throws java.io.IOException if there is an error
         * @throws NullPointerException if source array is null
         * @throws IllegalArgumentException if source array, offset, or length are invalid
         * @since 2.3.1
         */
        static byte[] encodeBytesToBytes( byte[] source, int off, int len, int options ) {

            if( source == null ){
                throw new NullPointerException( "Cannot serialize a null array." );
            }   // end if: null

            if( off < 0 ){
                throw new IllegalArgumentException( "Cannot have negative offset: " + off );
            }   // end if: off < 0

            if( len < 0 ){
                throw new IllegalArgumentException( "Cannot have length offset: " + len );
            }   // end if: len < 0

            if( off + len > source.length  ){
                throw new IllegalArgumentException(
                        String.format( "Cannot have offset of %d and length of %d with array of length %d", off,len,source.length));
            }   // end if: off < 0

            boolean breakLines = (options & DO_BREAK_LINES) > 0;

            //int    len43   = len * 4 / 3;
            //byte[] outBuff = new byte[   ( len43 )                      // Main 4:3
            //                           + ( (len % 3) > 0 ? 4 : 0 )      // Account for padding
            //                           + (breakLines ? ( len43 / MAX_LINE_LENGTH ) : 0) ]; // New lines
            // Try to determine more precisely how big the array needs to be.
            // If we get it right, we don't have to do an array copy, and
            // we save a bunch of memory.
            int encLen = ( len / 3 ) * 4 + ( len % 3 > 0 ? 4 : 0 ); // Bytes needed for actual encoding
            if( breakLines ){
                encLen += encLen / MAX_LINE_LENGTH; // Plus extra newline characters
            }
            byte[] outBuff = new byte[ encLen ];


            int d = 0;
            int e = 0;
            int len2 = len - 2;
            int lineLength = 0;
            for( ; d < len2; d+=3, e+=4 ) {
                encode3to4( source, d+off, 3, outBuff, e, options );

                lineLength += 4;
                if( breakLines && lineLength >= MAX_LINE_LENGTH )
                {
                    outBuff[e+4] = NEW_LINE;
                    e++;
                    lineLength = 0;
                }   // end if: end of line
            }   // en dfor: each piece of array

            if( d < len ) {
                encode3to4( source, d+off, len - d, outBuff, e, options );
                e += 4;
            }   // end if: some padding needed


            // Only resize array if we didn't guess it right.
            if( e <= outBuff.length - 1 ){
                byte[] finalOut = new byte[e];
                System.arraycopy(outBuff,0, finalOut,0,e);
                //System.err.println("Having to resize array from " + outBuff.length + " to " + e );
                return finalOut;
            } else {
                //System.err.println("No need to resize array.");
                return outBuff;
            }
        }


        /* ********  D E C O D I N G   M E T H O D S  ******** */


        /**
         * Decodes four bytes from array <var>source</var>
         * and writes the resulting bytes (up to three of them)
         * to <var>destination</var>.
         * The source and destination arrays can be manipulated
         * anywhere along their length by specifying
         * <var>srcOffset</var> and <var>destOffset</var>.
         * This method does not check to make sure your arrays
         * are large enough to accomodate <var>srcOffset</var> + 4 for
         * the <var>source</var> array or <var>destOffset</var> + 3 for
         * the <var>destination</var> array.
         * This method returns the actual number of bytes that
         * were converted from the Base64 encoding.
         * <p>This is the lowest level of the decoding methods with
         * all possible parameters.</p>
         *
         *
         * @param source the array to convert
         * @param srcOffset the index where conversion begins
         * @param destination the array to hold the conversion
         * @param destOffset the index where output will be put
         * @param options alphabet type is pulled from this (standard, url-safe, ordered)
         * @return the number of decoded bytes converted
         * @throws NullPointerException if source or destination arrays are null
         * @throws IllegalArgumentException if srcOffset or destOffset are invalid
         *         or there is not enough room in the array.
         * @since 1.3
         */
        private static int decode4to3(
                byte[] source, int srcOffset,
                byte[] destination, int destOffset, int options ) {

            // Lots of error checking and exception throwing
            if( source == null ){
                throw new NullPointerException( "Source array was null." );
            }   // end if
            if( destination == null ){
                throw new NullPointerException( "Destination array was null." );
            }   // end if
            if( srcOffset < 0 || srcOffset + 3 >= source.length ){
                throw new IllegalArgumentException( String.format(
                        "Source array with length %d cannot have offset of %d and still process four bytes.", source.length, srcOffset ) );
            }   // end if
            if( destOffset < 0 || destOffset +2 >= destination.length ){
                throw new IllegalArgumentException( String.format(
                        "Destination array with length %d cannot have offset of %d and still store three bytes.", destination.length, destOffset ) );
            }   // end if


            byte[] DECODABET = getDecodabet( options );

            // Example: Dk==
            if( source[ srcOffset + 2] == EQUALS_SIGN ) {
                // Two ways to do the same thing. Don't know which way I like best.
                //int outBuff =   ( ( DECODABET[ source[ srcOffset    ] ] << 24 ) >>>  6 )
                //              | ( ( DECODABET[ source[ srcOffset + 1] ] << 24 ) >>> 12 );
                int outBuff =   ( ( DECODABET[ source[ srcOffset    ] ] & 0xFF ) << 18 )
                        | ( ( DECODABET[ source[ srcOffset + 1] ] & 0xFF ) << 12 );

                destination[ destOffset ] = (byte)( outBuff >>> 16 );
                return 1;
            }

            // Example: DkL=
            else if( source[ srcOffset + 3 ] == EQUALS_SIGN ) {
                // Two ways to do the same thing. Don't know which way I like best.
                //int outBuff =   ( ( DECODABET[ source[ srcOffset     ] ] << 24 ) >>>  6 )
                //              | ( ( DECODABET[ source[ srcOffset + 1 ] ] << 24 ) >>> 12 )
                //              | ( ( DECODABET[ source[ srcOffset + 2 ] ] << 24 ) >>> 18 );
                int outBuff =   ( ( DECODABET[ source[ srcOffset     ] ] & 0xFF ) << 18 )
                        | ( ( DECODABET[ source[ srcOffset + 1 ] ] & 0xFF ) << 12 )
                        | ( ( DECODABET[ source[ srcOffset + 2 ] ] & 0xFF ) <<  6 );

                destination[ destOffset     ] = (byte)( outBuff >>> 16 );
                destination[ destOffset + 1 ] = (byte)( outBuff >>>  8 );
                return 2;
            }

            // Example: DkLE
            else {
                // Two ways to do the same thing. Don't know which way I like best.
                //int outBuff =   ( ( DECODABET[ source[ srcOffset     ] ] << 24 ) >>>  6 )
                //              | ( ( DECODABET[ source[ srcOffset + 1 ] ] << 24 ) >>> 12 )
                //              | ( ( DECODABET[ source[ srcOffset + 2 ] ] << 24 ) >>> 18 )
                //              | ( ( DECODABET[ source[ srcOffset + 3 ] ] << 24 ) >>> 24 );
                int outBuff =   ( ( DECODABET[ source[ srcOffset     ] ] & 0xFF ) << 18 )
                        | ( ( DECODABET[ source[ srcOffset + 1 ] ] & 0xFF ) << 12 )
                        | ( ( DECODABET[ source[ srcOffset + 2 ] ] & 0xFF ) <<  6)
                        | ( ( DECODABET[ source[ srcOffset + 3 ] ] & 0xFF )      );


                destination[ destOffset     ] = (byte)( outBuff >> 16 );
                destination[ destOffset + 1 ] = (byte)( outBuff >>  8 );
                destination[ destOffset + 2 ] = (byte)( outBuff       );

                return 3;
            }
        }

        /**
         * Low-level access to decoding ASCII characters in
         * the form of a byte array. <strong>Ignores GUNZIP option, if
         * it's set.</strong> This is not generally a recommended method,
         * although it is used internally as part of the decoding process.
         * Special case: if len = 0, an empty array is returned. Still,
         * if you need more speed and reduced memory footprint (and aren't
         * gzipping), consider this method.
         *
         * @param source The Base64 encoded data
         * @param off    The offset of where to begin decoding
         * @param len    The length of characters to decode
         * @param options Can specify options such as alphabet type to use
         * @return decoded data
         * @throws IllegalArgumentException If bogus characters exist in source data
         */
        static byte[] decode( byte[] source, int off, int len, int options ) {

            // Lots of error checking and exception throwing
            if( source == null ){
                throw new NullPointerException( "Cannot decode null source array." );
            }   // end if
            if( off < 0 || off + len > source.length ){
                throw new IllegalArgumentException( String.format(
                        "Source array with length %d cannot have offset of %d and process %d bytes.", source.length, off, len ) );
            }   // end if

            if( len == 0 ){
                return new byte[0];
            }else if( len < 4 ){
                throw new IllegalArgumentException(
                        "Base64-encoded string must have at least four characters, but length specified was " + len );
            }   // end if

            byte[] DECODABET = getDecodabet( options );

            int    len34   = len * 3 / 4;       // Estimate on array size
            byte[] outBuff = new byte[ len34 ]; // Upper limit on size of output
            int    outBuffPosn = 0;             // Keep track of where we're writing

            byte[] b4        = new byte[4];     // Four byte buffer from source, eliminating white space
            int    b4Posn    = 0;               // Keep track of four byte input buffer
            int    i         = 0;               // Source array counter
            byte   sbiDecode = 0;               // Special value from DECODABET

            for(i = off; i < off+len; i++ ) {  // Loop through source

                sbiDecode = DECODABET[ source[i]&0xFF ];

                // White space, Equals sign, or legit Base64 character
                // Note the values such as -5 and -9 in the
                // DECODABETs at the top of the file.
                if( sbiDecode >= WHITE_SPACE_ENC )  {
                    if( sbiDecode >= EQUALS_SIGN_ENC ) {
                        b4[ b4Posn++ ] = source[i];         // Save non-whitespace
                        if( b4Posn > 3 ) {                  // Time to decode?
                            outBuffPosn += decode4to3( b4, 0, outBuff, outBuffPosn, options );
                            b4Posn = 0;

                            // If that was the equals sign, break out of 'for' loop
                            if( source[i] == EQUALS_SIGN ) {
                                break;
                            }
                        }
                    }
                }
                else {
                    // There's a bad input character in the Base64 stream.
                    throw new InvalidBase64CharacterException( String.format(
                            "Bad Base64 input character decimal %d in array position %d", ((int)source[i])&0xFF, i ) );
                }
            }

            byte[] out = new byte[ outBuffPosn ];
            System.arraycopy( outBuff, 0, out, 0, outBuffPosn );
            return out;
        }
    }


    static class InvalidBase64CharacterException extends IllegalArgumentException {

        InvalidBase64CharacterException(String message) {
            super(message);
        }
    }

}
