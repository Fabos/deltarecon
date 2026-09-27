package com.negro.bridge;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;

import javax.swing.*;
import java.awt.*;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Negro Burp Bridge v0.12
 *
 * Observa respuestas generadas por cualquier herramienta de Burp y envía el par
 * request/response al API local de Negro. No modifica tráfico y no filtra assets.
 * Negro decide si el host pertenece a uno de sus targets y deduplica evidencia.
 */
public class NegroBurpBridge implements BurpExtension {
    private MontoyaApi api;
    private final HttpClient client = HttpClient.newBuilder()
            // Negro local corre sobre HTTP claro (Uvicorn). Java HttpClient puede
            // intentar negociar HTTP/2 mediante h2c/Upgrade; con algunos ASGI
            // servers ese upgrade hace que el POST llegue sin body. Forzamos
            // HTTP/1.1 para que el payload JSON se entregue de forma estable.
            .version(HttpClient.Version.HTTP_1_1)
            .connectTimeout(Duration.ofSeconds(2))
            .build();
    private final AtomicLong accepted = new AtomicLong();
    private final AtomicLong ignored = new AtomicLong();
    private final AtomicLong errors = new AtomicLong();
    private volatile String negroBaseUrl = System.getProperty("negro.url", "http://127.0.0.1:8765");
    private JLabel statusLabel;
    private final ScheduledExecutorService bridgePoller = Executors.newSingleThreadScheduledExecutor(r -> { Thread t = new Thread(r, "negro-repeater-bridge"); t.setDaemon(true); return t; });

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("Negro Burp Bridge");
        api.logging().logToOutput("Negro Burp Bridge v0.12.0 iniciado → " + negroBaseUrl);
        api.http().registerHttpHandler(new BridgeHttpHandler());
        api.userInterface().registerSuiteTab("Negro", buildPanel());
        healthCheck();
        bridgePoller.scheduleWithFixedDelay(this::pollRepeaterQueue, 1, 1, TimeUnit.SECONDS);
    }

    private Component buildPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(BorderFactory.createEmptyBorder(16, 16, 16, 16));

        JLabel title = new JLabel("Negro Burp Bridge");
        title.setFont(title.getFont().deriveFont(Font.BOLD, 18f));
        panel.add(title);
        panel.add(Box.createVerticalStrut(8));
        panel.add(new JLabel("Envía tráfico HTTP observado por Burp a Negro en tiempo real."));
        panel.add(Box.createVerticalStrut(12));

        JPanel endpoint = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        endpoint.add(new JLabel("Negro URL:"));
        JTextField field = new JTextField(negroBaseUrl, 36);
        endpoint.add(field);
        JButton apply = new JButton("Aplicar");
        endpoint.add(apply);
        panel.add(endpoint);

        statusLabel = new JLabel("Comprobando conexión…");
        panel.add(Box.createVerticalStrut(10));
        panel.add(statusLabel);
        panel.add(Box.createVerticalStrut(8));

        JLabel counters = new JLabel();
        panel.add(counters);
        Timer timer = new Timer(1000, e -> counters.setText(
                "Aceptados: " + accepted.get() + "   Fuera de scope: " + ignored.get() + "   Errores: " + errors.get()));
        timer.start();

        apply.addActionListener(e -> {
            String value = field.getText().trim().replaceAll("/+$", "");
            if (!value.startsWith("http://") && !value.startsWith("https://")) {
                statusLabel.setText("URL inválida: usa http:// o https://");
                return;
            }
            negroBaseUrl = value;
            healthCheck();
        });
        return panel;
    }

    private void healthCheck() {
        java.net.http.HttpRequest req = java.net.http.HttpRequest.newBuilder()
                .uri(URI.create(negroBaseUrl + "/api/ingest/health"))
                .timeout(Duration.ofSeconds(3))
                .GET().build();
        client.sendAsync(req, BodyHandlers.ofString())
                .thenAccept(r -> SwingUtilities.invokeLater(() -> {
                    if (statusLabel != null) statusLabel.setText(r.statusCode() == 200 ? "Conectado a Negro ✓" : "Negro respondió HTTP " + r.statusCode());
                }))
                .exceptionally(ex -> {
                    SwingUtilities.invokeLater(() -> { if (statusLabel != null) statusLabel.setText("Negro no disponible: " + ex.getClass().getSimpleName()); });
                    return null;
                });
    }

    private final class BridgeHttpHandler implements HttpHandler {
        @Override
        public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
            return RequestToBeSentAction.continueWith(request);
        }

        @Override
        public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
            try {
                HttpRequest request = response.initiatingRequest();
                if (isNegroBridgeTraffic(request.url())) {
                    return ResponseReceivedAction.continueWith(response);
                }
                String tool = response.toolSource().toolType().name();
                String json = toJson(request, response, tool);
                sendAsync(json, request.method(), request.url(), tool);
            } catch (Exception ex) {
                errors.incrementAndGet();
                api.logging().logToError("Negro Bridge: " + ex.getMessage());
            }
            return ResponseReceivedAction.continueWith(response);
        }
    }

    private void pollRepeaterQueue() {
        try {
            java.net.http.HttpRequest req = java.net.http.HttpRequest.newBuilder()
                    .uri(URI.create(negroBaseUrl + "/api/bridge/repeater/next"))
                    .timeout(Duration.ofSeconds(3)).GET().build();
            client.sendAsync(req, BodyHandlers.ofString()).thenAccept(resp -> {
                if (resp.statusCode() != 200) return;
                String body = resp.body();
                if (!body.contains("\"pending\":true") && !body.contains("\"pending\": true")) return;
                String targetKey = jsonString(body, "target_key");
                String url = jsonString(body, "url");
                String method = jsonString(body, "method");
                String caption = jsonString(body, "caption");
                String requestB64 = jsonString(body, "request_b64");
                long queueId = jsonLong(body, "id");
                boolean ok = false;
                String error = "";
                try {
                    HttpRequest request;
                    if (requestB64 != null && !requestB64.isBlank()) {
                        URI u = URI.create(url);
                        boolean secure = "https".equalsIgnoreCase(u.getScheme());
                        int port = u.getPort() > 0 ? u.getPort() : (secure ? 443 : 80);
                        HttpService service = HttpService.httpService(u.getHost(), port, secure);
                        byte[] raw = Base64.getDecoder().decode(requestB64);
                        request = HttpRequest.httpRequest(service, ByteArray.byteArray(raw));
                    } else {
                        request = HttpRequest.httpRequestFromUrl(url).withMethod(method == null || method.isBlank() ? "GET" : method);
                    }
                    api.repeater().sendToRepeater(request, caption == null || caption.isBlank() ? "From Negro" : caption);
                    ok = true;
                    api.logging().logToOutput("Negro → Repeater: " + request.method() + " " + request.url());
                } catch (Exception ex) {
                    error = ex.getMessage() == null ? ex.getClass().getSimpleName() : ex.getMessage();
                    api.logging().logToError("Negro → Repeater falló: " + error);
                }
                ackRepeater(targetKey, queueId, ok, error);
            });
        } catch (Exception ignored) {
        }
    }

    private void ackRepeater(String targetKey, long queueId, boolean ok, String error) {
        if (targetKey == null || queueId <= 0) return;
        String json = "{\"ok\":" + ok + "," + kv("error", error == null ? "" : error) + "}";
        java.net.http.HttpRequest req = java.net.http.HttpRequest.newBuilder()
                .uri(URI.create(negroBaseUrl + "/api/bridge/repeater/" + targetKey + "/" + queueId + "/ack"))
                .timeout(Duration.ofSeconds(3)).header("Content-Type", "application/json")
                .POST(BodyPublishers.ofString(json, StandardCharsets.UTF_8)).build();
        client.sendAsync(req, BodyHandlers.discarding());
    }

    private String jsonString(String json, String key) {
        Pattern p = Pattern.compile("\\\"" + Pattern.quote(key) + "\\\"\\s*:\\s*(null|\\\"((?:\\\\.|[^\\\"])*)\\\")");
        Matcher m = p.matcher(json);
        if (!m.find() || "null".equals(m.group(1))) return null;
        return unescapeJson(m.group(2));
    }

    private long jsonLong(String json, String key) {
        Pattern p = Pattern.compile("\\\"" + Pattern.quote(key) + "\\\"\\s*:\\s*(\\d+)");
        Matcher m = p.matcher(json);
        return m.find() ? Long.parseLong(m.group(1)) : -1;
    }

    private String unescapeJson(String value) {
        if (value == null) return null;
        return value.replace("\\\"", "\"").replace("\\\\", "\\").replace("\\n", "\n").replace("\\r", "\r").replace("\\t", "\t");
    }

    private void sendAsync(String json, String method, String observedUrl, String tool) {
        byte[] payload = json.getBytes(StandardCharsets.UTF_8);
        String first = payload.length == 0 ? "<empty>" : String.format("0x%02x('%s')", payload[0] & 0xff, payload[0] >= 32 && payload[0] <= 126 ? Character.toString((char) payload[0]) : ".");
        api.logging().logToOutput("Negro → ingest: " + tool + " " + method + " " + observedUrl + " | payload=" + payload.length + " bytes | first=" + first);

        java.net.http.HttpRequest req = java.net.http.HttpRequest.newBuilder()
                .uri(URI.create(negroBaseUrl + "/api/ingest/http"))
                .timeout(Duration.ofSeconds(5))
                .header("Content-Type", "application/json; charset=utf-8")
                .header("Accept", "application/json")
                .POST(BodyPublishers.ofByteArray(payload))
                .build();
        client.sendAsync(req, BodyHandlers.ofString(StandardCharsets.UTF_8))
                .thenAccept(resp -> {
                    String body = resp.body();
                    if (resp.statusCode() >= 200 && resp.statusCode() < 300) {
                        if (body.contains("\"accepted\":true") || body.contains("\"accepted\": true")) {
                            accepted.incrementAndGet();
                            api.logging().logToOutput("Negro ← ingest HTTP " + resp.statusCode() + " accepted=true");
                        } else {
                            ignored.incrementAndGet();
                            api.logging().logToOutput("Negro ← ingest HTTP " + resp.statusCode() + " accepted=false");
                        }
                    } else {
                        errors.incrementAndGet();
                        api.logging().logToError("Negro ingest HTTP " + resp.statusCode() + ": " + body);
                    }
                })
                .exceptionally(ex -> {
                    errors.incrementAndGet();
                    api.logging().logToError("Negro ingest exception: " + ex.getClass().getSimpleName() + ": " + (ex.getMessage() == null ? "" : ex.getMessage()));
                    return null;
                });
    }

    private boolean isNegroBridgeTraffic(String url) {
        try {
            URI observed = URI.create(url);
            URI negro = URI.create(negroBaseUrl);
            int observedPort = observed.getPort() > 0 ? observed.getPort() : ("https".equalsIgnoreCase(observed.getScheme()) ? 443 : 80);
            int negroPort = negro.getPort() > 0 ? negro.getPort() : ("https".equalsIgnoreCase(negro.getScheme()) ? 443 : 80);
            return observed.getHost() != null && negro.getHost() != null
                    && observed.getHost().equalsIgnoreCase(negro.getHost())
                    && observedPort == negroPort;
        } catch (Exception ignored) {
            return false;
        }
    }

    private String toJson(HttpRequest request, HttpResponseReceived response, String tool) {
        boolean authenticated = request.hasHeader("Cookie") || request.hasHeader("Authorization");
        String requestType = nullToEmpty(request.headerValue("Content-Type"));
        String responseType = nullToEmpty(response.headerValue("Content-Type"));
        String requestB64 = Base64.getEncoder().encodeToString(request.toByteArray().getBytes());
        String responseB64 = Base64.getEncoder().encodeToString(response.toByteArray().getBytes());
        String responseBodyB64 = Base64.getEncoder().encodeToString(response.body().getBytes());

        return "{" +
                kv("url", request.url()) + "," +
                kv("method", request.method()) + "," +
                kv("tool", tool) + "," +
                "\"status_code\":" + response.statusCode() + "," +
                "\"authenticated\":" + authenticated + "," +
                kv("request_content_type", requestType) + "," +
                kv("response_content_type", responseType) + "," +
                kv("query", nullToEmpty(request.query())) + "," +
                "\"request_headers\":" + headersJson(request.headers()) + "," +
                "\"response_headers\":" + headersJson(response.headers()) + "," +
                kv("request_b64", requestB64) + "," +
                kv("response_b64", responseB64) + "," +
                kv("response_body_b64", responseBodyB64) +
                "}";
    }

    private String headersJson(List<HttpHeader> headers) {
        return headers.stream()
                .map(h -> "{" + kv("name", h.name()) + "," + kv("value", h.value()) + "}")
                .collect(Collectors.joining(",", "[", "]"));
    }

    private String kv(String key, String value) {
        return "\"" + escape(key) + "\":\"" + escape(nullToEmpty(value)) + "\"";
    }

    private String nullToEmpty(String value) {
        return value == null ? "" : value;
    }

    private String escape(String value) {
        // Emit ASCII-only JSON strings. Burp can expose header/body metadata with
        // Unicode code points that are valid in Java strings but may become invalid
        // UTF-8/JSON when manually concatenated. Escaping every non-ASCII UTF-16
        // code unit keeps the wire payload deterministic and standards-compliant.
        StringBuilder b = new StringBuilder(value.length() + 32);
        for (char c : value.toCharArray()) {
            switch (c) {
                case '\\' -> b.append("\\\\");
                case '"' -> b.append("\\\"");
                case '\b' -> b.append("\\b");
                case '\f' -> b.append("\\f");
                case '\n' -> b.append("\\n");
                case '\r' -> b.append("\\r");
                case '\t' -> b.append("\\t");
                default -> {
                    if (c < 0x20 || c > 0x7e) b.append(String.format("\\u%04x", (int) c));
                    else b.append(c);
                }
            }
        }
        return b.toString();
    }
}
