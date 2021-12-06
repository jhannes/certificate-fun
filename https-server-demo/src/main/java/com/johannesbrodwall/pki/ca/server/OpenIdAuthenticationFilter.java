package com.johannesbrodwall.pki.ca.server;

import org.eclipse.jetty.security.DefaultUserIdentity;
import org.eclipse.jetty.security.UserAuthentication;
import org.eclipse.jetty.server.Authentication;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Response;
import org.eclipse.jetty.server.UserIdentity;
import org.jsonbuddy.JsonObject;
import org.jsonbuddy.parse.JsonHttpException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.security.Principal;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static java.nio.charset.StandardCharsets.UTF_8;

public class OpenIdAuthenticationFilter implements Filter {
    private static final Logger logger = LoggerFactory.getLogger(OpenIdAuthenticationFilter.class);

    private String discoveryUrl = "https://login.microsoftonline.com/common/.well-known/openid-configuration";
    private Optional<String> clientId = Optional.empty();
    private Optional<String> clientSecret = Optional.empty();

    public void setConfig(Map<String, String> config) {
        discoveryUrl = config.getOrDefault("discoveryUrl", "https://login.microsoftonline.com/common/.well-known/openid-configuration");
        clientId = Optional.ofNullable(config.getOrDefault("clientId", null));
        clientSecret = Optional.ofNullable(config.getOrDefault("clientSecret", null));
    }

    public static class OpenIdPrincipal implements Principal {
        private final JsonObject userinfo;

        public OpenIdPrincipal(JsonObject userinfo) {
            this.userinfo = userinfo;
        }

        @Override
        public String getName() {
            return userinfo.stringValue("email")
                    .or(() -> userinfo.stringValue("unique_name"))
                    .or(() -> userinfo.stringValue("name"))
                    .or(() -> userinfo.stringValue("sub"))
                    .orElseGet(userinfo::toJson);
        }

        public JsonObject getUserinfo() {
            return userinfo;
        }
    }


    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        Request request = (Request) servletRequest;
        request.setAuthentication(new OpenIdAuthentication());

        if ("/login".equals(request.getServletPath())) {
            redirectToAuthorize(request, (Response)response);
        } else if ("/login/oauth2callback".equals(request.getServletPath())) {
            oauth2callback(request, (Response)response);
        } else if ("/login/endsession".equals(request.getServletPath())) {
            endSession(request, (Response)response);
        } else {
            chain.doFilter(servletRequest, response);
        }
    }

    private JsonObject getDiscoveryDocument() throws IOException {
        return JsonObject.read(new URL(discoveryUrl));
    }

    private String getClientId() {
        return clientId.orElseThrow(() -> new RuntimeException("Missing clientId configuration"));
    }

    private String getClientSecret() {
        return clientSecret.orElseThrow(() -> new RuntimeException("Missing clientSecret configuration"));
    }

    private void redirectToAuthorize(Request request, Response response) throws IOException {
        String state = UUID.randomUUID().toString();
        Cookie stateCookie = new Cookie("authorization_state", state);
        stateCookie.setPath(request.getContextPath());
        response.addCookie(stateCookie);

        String redirectUri = request.getRequestURL() + "/oauth2callback";

        Map<String, String> parameters = Map.of(
                "response_type", "code",
                "state", state,
                "client_id", getClientId(),
                "redirect_uri", redirectUri,
                "scope", "openid+email+profile"
        );

        response.sendRedirect(
                getDiscoveryDocument().requiredString("authorization_endpoint") + "?" + toHttpQuery(parameters)
        );
    }
    private void oauth2callback(Request request, Response response) throws IOException {
        String authorizationCode = getCookie(request, "authorization_state").orElse(null);
        if (!Objects.equals(request.getParameter("state"), authorizationCode)) {
            throw new IOException("401 Illegal state");
        }

        Map<String, String> payload = Map.of(
                "grant_type", "authorization_code",
                "client_id", getClientId(),
                "client_secret", getClientSecret(),
                "redirect_uri", request.getRequestURL().toString(),
                "code", request.getParameter("code")
        );


        HttpURLConnection connection = (HttpURLConnection) new URL(getDiscoveryDocument().requiredString("token_endpoint")).openConnection();
        connection.setRequestMethod("POST");
        connection.setDoOutput(true);
        connection.getOutputStream().write(toHttpQuery(payload).getBytes());

        JsonObject tokenResponse = JsonObject.read(connection);

        Cookie tokenCookie = new Cookie("access_token", tokenResponse.requiredString("access_token"));
        tokenCookie.setMaxAge((int) tokenResponse.requiredLong("expires_in"));
        tokenCookie.setPath(request.getContextPath());
        response.addCookie(tokenCookie);
        response.addCookie(removeCookie("authorization_state", request));
        response.sendRedirect(request.getContextPath());
    }

    private void endSession(Request request, Response response) throws IOException {
        response.addCookie(removeCookie("access_token", request));
        JsonObject discoveryDocument = getDiscoveryDocument();

        response.sendRedirect(
                discoveryDocument.requiredString("end_session_endpoint") + "?" + toHttpQuery(Map.of("post_logout_redirect_uri", request.getRootURL() + request.getContextPath()))
        );
    }

    private Optional<JsonObject> fetchUserinfo(String accessToken) {
        try {
            logger.debug("Fetching user info for access token");
            JsonObject discoveryDocument = getDiscoveryDocument();

            HttpURLConnection connection = (HttpURLConnection) new URL(discoveryDocument.requiredString("userinfo_endpoint")).openConnection();
            connection.setRequestProperty("Authorization", "Bearer " + accessToken);

            return Optional.ofNullable(JsonObject.read(connection));
        } catch (JsonHttpException | IOException e) {
            logger.info("Could not fetch userinfo for access token", e);
            return Optional.empty();
        }
    }

    private Optional<String> getCookie(Request request, String name) {
        if (request.getCookies() == null) {
            return Optional.empty();
        }
        return Stream.of(request.getCookies())
                .filter(c -> c.getName().equals(name))
                .map(Cookie::getValue)
                .filter(s -> !s.isBlank())
                .findAny();
    }

    private Cookie removeCookie(String name, Request request) {
        Cookie cookie = new Cookie(name, null);
        cookie.setMaxAge(-1);
        cookie.setPath(request.getContextPath());
        return cookie;
    }

    private String toHttpQuery(Map<String, String> parameters) {
        return parameters.entrySet().stream()
                .map(entry -> URLEncoder.encode(entry.getKey(), UTF_8) + "=" + URLEncoder.encode(entry.getValue(), UTF_8))
                .collect(Collectors.joining("&"));
    }

    private class OpenIdAuthentication implements Authentication.Deferred {
        @Override
        public Authentication authenticate(ServletRequest servletRequest) {
            Request request = (Request) servletRequest;

            return getCookie(request, "access_token")
                    .flatMap(OpenIdAuthenticationFilter.this::fetchUserinfo)
                    .map(this::createUserAuthentication)
                    .orElse(this);
        }

        @Override
        public Authentication authenticate(ServletRequest request, ServletResponse response) {
            return null;
        }

        @Override
        public Authentication login(String username, Object password, ServletRequest request) {
            return null;
        }

        @Override
        public Authentication logout(ServletRequest request) {
            return null;
        }

        private Authentication createUserAuthentication(JsonObject json) {
            return new UserAuthentication("OpenId", createUserIdentity(new OpenIdPrincipal(json)));
        }

        private UserIdentity createUserIdentity(OpenIdPrincipal principal) {
            return new DefaultUserIdentity(new Subject(false, Set.of(principal), Set.of(), Set.of()), principal, new String[0]);
        }
    }
}
