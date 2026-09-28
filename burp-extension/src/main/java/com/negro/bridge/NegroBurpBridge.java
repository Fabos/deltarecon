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
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.*;
import java.awt.*;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Negro Burp Bridge v0.14
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
        api.logging().logToOutput("Negro Burp Bridge v0.16.3 iniciado → " + negroBaseUrl);
        api.http().registerHttpHandler(new BridgeHttpHandler());
        api.userInterface().registerContextMenuItemsProvider(new NegroContextMenu());
        api.userInterface().registerSuiteTab("Negro", buildPanel());
        healthCheck();
        bridgePoller.scheduleWithFixedDelay(this::pollRepeaterQueue, 1, 1, TimeUnit.SECONDS);
        api.logging().logToOutput("Negro → Repeater poller activo · consultando /api/bridge/repeater/next cada 1s");
    }

    private Component buildPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(BorderFactory.createEmptyBorder(16, 16, 16, 16));

        JLabel title = new JLabel("Negro Burp Bridge");
        title.setFont(title.getFont().deriveFont(Font.BOLD, 18f));
        panel.add(title);
        panel.add(Box.createVerticalStrut(8));
        panel.add(new JLabel("Sincroniza tráfico con Negro y añade acciones contextuales desde cualquier request/response."));
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
                    .timeout(Duration.ofSeconds(3))
                    .header("Accept", "application/json")
                    .GET().build();

            // Use a synchronous call on the dedicated poller thread. In v0.16.2 an
            // unobserved CompletableFuture failure could claim a queue item server-side
            // without ever running the thenAccept callback, leaving the item stuck in
            // "claimed" and producing no Burp logs. Blocking here is safe because this
            // method already runs on a single daemon ScheduledExecutorService.
            java.net.http.HttpResponse<String> resp = client.send(req, BodyHandlers.ofString(StandardCharsets.UTF_8));
            String body = resp.body() == null ? "" : resp.body();
            boolean pending = Pattern.compile("\"pending\"\\s*:\\s*true").matcher(body).find();
            api.logging().logToOutput("Negro → Repeater poll: HTTP " + resp.statusCode() + " · body=" + body.length() + " chars · pending=" + pending);
            if (resp.statusCode() != 200 || !pending) return;

            api.logging().logToOutput("Negro → Repeater: item pendiente recibido del backend");
            String targetKey = jsonString(body, "target_key");
            String url = jsonString(body, "url");
            String method = jsonString(body, "method");
            String caption = jsonString(body, "caption");
            String requestB64 = jsonString(body, "request_b64");
            long queueId = jsonLong(body, "id");
            api.logging().logToOutput("Negro → Repeater claim: queue=" + queueId + " target=" + targetKey + " method=" + method + " url=" + url + " b64chars=" + (requestB64 == null ? 0 : requestB64.length()));
            boolean ok = false;
            String error = "";
            try {
                HttpRequest request;
                URI u = URI.create(url);
                boolean secure = "https".equalsIgnoreCase(u.getScheme());
                int port = u.getPort() > 0 ? u.getPort() : (secure ? 443 : 80);
                HttpService service = HttpService.httpService(u.getHost(), port, secure);
                int rawLength = 0;
                boolean normalizedHttp2 = false;
                if (requestB64 != null && !requestB64.isBlank()) {
                    byte[] raw = Base64.getDecoder().decode(requestB64);
                    rawLength = raw.length;
                    byte[] repeaterRaw = normalizeRawRequestForRepeater(raw);
                    normalizedHttp2 = repeaterRaw != raw;
                    request = HttpRequest.httpRequest(service, ByteArray.byteArray(repeaterRaw));
                    if (request.toByteArray().length() == 0 || request.method() == null || request.method().isBlank()) {
                        api.logging().logToError("Negro → Repeater: request reconstruida vacía; usando fallback URL. queue=" + queueId + " raw=" + rawLength + "B");
                        request = fallbackRequest(url, method, service);
                    }
                } else {
                    request = fallbackRequest(url, method, service);
                }
                String tabName = caption == null || caption.isBlank() ? "Negro · " + (method == null ? "GET" : method) : caption;
                api.repeater().sendToRepeater(request, tabName);
                ok = true;
                api.logging().logToOutput("Negro → Repeater: queue=" + queueId + " raw=" + rawLength + "B reconstructed=" + request.toByteArray().length() + "B h2_normalized=" + normalizedHttp2 + " · " + request.method() + " " + request.url());
            } catch (Exception ex) {
                error = ex.getMessage() == null ? ex.getClass().getSimpleName() : ex.getMessage();
                api.logging().logToError("Negro → Repeater falló: " + error);
            }
            ackRepeater(targetKey, queueId, ok, error);
        } catch (Exception ex) {
            String msg = ex.getMessage() == null ? ex.getClass().getSimpleName() : ex.getMessage();
            api.logging().logToError("Negro → Repeater poll falló: " + msg);
        }
    }

    /**
     * Montoya stores observed HTTP/2 messages in a readable raw form whose request line
     * can end in "HTTP/2". The generic httpRequest(service, ByteArray) factory is aimed
     * at HTTP/1-style message syntax and some Burp builds render such reconstructed
     * HTTP/2 raw messages as an empty Repeater tab. For the hand-off only, normalize the
     * textual request line to HTTP/1.1 while preserving every other byte (headers/body).
     * Repeater can still negotiate HTTP/2 when the request is sent, according to Burp's
     * Repeater settings.
     */
    private byte[] normalizeRawRequestForRepeater(byte[] raw) {
        if (raw == null || raw.length == 0) return raw;
        int lineEnd = -1;
        for (int i = 0; i + 1 < raw.length; i++) {
            if (raw[i] == '\r' && raw[i + 1] == '\n') { lineEnd = i; break; }
        }
        if (lineEnd < 0) {
            for (int i = 0; i < raw.length; i++) {
                if (raw[i] == '\n') { lineEnd = i; break; }
            }
        }
        if (lineEnd <= 0) return raw;
        String firstLine = new String(raw, 0, lineEnd, StandardCharsets.ISO_8859_1);
        if (!(firstLine.endsWith(" HTTP/2") || firstLine.endsWith(" HTTP/2.0"))) return raw;
        String normalized = firstLine.replaceFirst(" HTTP/2(?:\\.0)?$", " HTTP/1.1");
        byte[] head = normalized.getBytes(StandardCharsets.ISO_8859_1);
        byte[] out = new byte[head.length + (raw.length - lineEnd)];
        System.arraycopy(head, 0, out, 0, head.length);
        System.arraycopy(raw, lineEnd, out, head.length, raw.length - lineEnd);
        return out;
    }

    private HttpRequest fallbackRequest(String url, String method, HttpService service) {
        String m = method == null || method.isBlank() ? "GET" : method;
        try {
            URI u = URI.create(url);
            String path = u.getRawPath();
            if (path == null || path.isBlank()) path = "/";
            if (u.getRawQuery() != null && !u.getRawQuery().isBlank()) path += "?" + u.getRawQuery();
            String host = u.getHost();
            int explicitPort = u.getPort();
            boolean defaultPort = explicitPort < 0 || ("https".equalsIgnoreCase(u.getScheme()) && explicitPort == 443) || ("http".equalsIgnoreCase(u.getScheme()) && explicitPort == 80);
            String hostHeader = host + (defaultPort ? "" : ":" + explicitPort);
            String raw = m + " " + path + " HTTP/1.1\r\nHost: " + hostHeader + "\r\nAccept: */*\r\n\r\n";
            return HttpRequest.httpRequest(service, raw);
        } catch (Exception ignored) {
            return HttpRequest.httpRequestFromUrl(url).withMethod(m).withService(service);
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


    private String toJson(HttpRequest request, HttpResponse response, String tool) {
        boolean authenticated = request.hasHeader("Cookie") || request.hasHeader("Authorization");
        String requestType = nullToEmpty(request.headerValue("Content-Type"));
        String responseType = response == null ? "" : nullToEmpty(response.headerValue("Content-Type"));
        String requestB64 = Base64.getEncoder().encodeToString(request.toByteArray().getBytes());
        String responseB64 = response == null ? "" : Base64.getEncoder().encodeToString(response.toByteArray().getBytes());
        String responseBodyB64 = response == null ? "" : Base64.getEncoder().encodeToString(response.body().getBytes());

        return "{" +
                kv("url", request.url()) + "," +
                kv("method", request.method()) + "," +
                kv("tool", tool) + "," +
                "\"status_code\":" + (response == null ? "null" : Short.toString(response.statusCode())) + "," +
                "\"authenticated\":" + authenticated + "," +
                kv("request_content_type", requestType) + "," +
                kv("response_content_type", responseType) + "," +
                kv("query", nullToEmpty(request.query())) + "," +
                "\"request_headers\":" + headersJson(request.headers()) + "," +
                "\"response_headers\":" + (response == null ? "[]" : headersJson(response.headers())) + "," +
                kv("request_b64", requestB64) + "," +
                kv("response_b64", responseB64) + "," +
                kv("response_body_b64", responseBodyB64) +
                "}";
    }

    private record BridgeContext(String targetKey, long resourceId, long operationId, long exchangeId, String webPath) {}

    private record FindingChoice(long id, String title, String severity, String status) {
        @Override public String toString() { return "#" + id + " · " + title + " · " + severity + " · " + status; }
    }

    private final class NegroContextMenu implements ContextMenuItemsProvider {
        @Override
        public List<Component> provideMenuItems(ContextMenuEvent event) {
            HttpRequestResponse rr = selectedRequestResponse(event);
            if (rr == null || rr.request() == null || isNegroBridgeTraffic(rr.request().url())) return List.of();
            JMenu menu = new JMenu("Negro");
            JMenuItem open = new JMenuItem("Open in Negro");
            JMenuItem interesting = new JMenuItem("Mark as Interesting");
            JMenuItem createFinding = new JMenuItem("Create Finding…");
            JMenuItem attachFinding = new JMenuItem("Attach to existing Finding…");
            JMenuItem retest = new JMenuItem("Attach as Retest evidence…");
            String tool = event.toolType() == null ? "OTHER" : event.toolType().name();
            open.addActionListener(e -> runContextAction("open", () -> openInNegro(rr, tool)));
            interesting.addActionListener(e -> runContextAction("interesting", () -> markInteresting(rr, tool)));
            createFinding.addActionListener(e -> runContextAction("finding", () -> createFindingFromBurp(rr, tool)));
            attachFinding.addActionListener(e -> runContextAction("attach", () -> attachFindingFromBurp(rr, tool)));
            retest.addActionListener(e -> runContextAction("retest", () -> attachRetestFromBurp(rr, tool)));
            menu.add(open); menu.add(interesting); menu.addSeparator(); menu.add(createFinding); menu.add(attachFinding); menu.addSeparator(); menu.add(retest);
            return List.of(menu);
        }
    }

    private HttpRequestResponse selectedRequestResponse(ContextMenuEvent event) {
        List<HttpRequestResponse> selected = event.selectedRequestResponses();
        if (selected != null && !selected.isEmpty()) return selected.get(0);
        return event.messageEditorRequestResponse().map(x -> x.requestResponse()).orElse(null);
    }

    private void runContextAction(String name, Runnable action) {
        Thread t = new Thread(() -> {
            try { action.run(); }
            catch (Exception ex) {
                api.logging().logToError("Negro context " + name + ": " + (ex.getMessage() == null ? ex.getClass().getSimpleName() : ex.getMessage()));
                showMessage("Negro", "No se pudo completar la acción: " + (ex.getMessage() == null ? ex.getClass().getSimpleName() : ex.getMessage()), JOptionPane.ERROR_MESSAGE);
            }
        }, "negro-context-" + name);
        t.setDaemon(true); t.start();
    }

    private BridgeContext ingestContext(HttpRequestResponse rr, String tool) {
        try {
            String payload = toJson(rr.request(), rr.hasResponse() ? rr.response() : null, tool == null ? "OTHER" : tool);
            java.net.http.HttpResponse<String> resp = postJson("/api/ingest/http", payload);
            String body = resp.body();
            if (resp.statusCode() < 200 || resp.statusCode() >= 300) throw new IllegalStateException("Negro ingest HTTP " + resp.statusCode());
            if (!body.contains("\"accepted\":true") && !body.contains("\"accepted\": true")) {
                String reason = jsonString(body, "reason");
                throw new IllegalStateException(reason == null ? "La request está fuera del scope de los targets de Negro" : reason);
            }
            String targetKey = jsonString(body, "target_key");
            long resourceId = jsonLong(body, "resource_id");
            long operationId = jsonLong(body, "operation_id");
            long exchangeId = jsonLong(body, "exchange_id");
            if (targetKey == null || resourceId <= 0) throw new IllegalStateException("Negro no devolvió contexto del resource");
            return new BridgeContext(targetKey, resourceId, operationId, exchangeId, "/t/" + targetKey + "/resource/" + resourceId);
        } catch (Exception ex) {
            if (ex instanceof RuntimeException re) throw re;
            throw new IllegalStateException(ex);
        }
    }

    private java.net.http.HttpResponse<String> postJson(String path, String json) throws Exception {
        java.net.http.HttpRequest req = java.net.http.HttpRequest.newBuilder()
                .uri(URI.create(negroBaseUrl + path)).timeout(Duration.ofSeconds(8))
                .header("Content-Type", "application/json; charset=utf-8").header("Accept", "application/json")
                .POST(BodyPublishers.ofByteArray(json.getBytes(StandardCharsets.UTF_8))).build();
        return client.send(req, BodyHandlers.ofString(StandardCharsets.UTF_8));
    }

    private String getText(String path) throws Exception {
        java.net.http.HttpRequest req = java.net.http.HttpRequest.newBuilder().uri(URI.create(negroBaseUrl + path)).timeout(Duration.ofSeconds(8)).GET().build();
        java.net.http.HttpResponse<String> resp = client.send(req, BodyHandlers.ofString(StandardCharsets.UTF_8));
        if (resp.statusCode() < 200 || resp.statusCode() >= 300) throw new IllegalStateException("Negro HTTP " + resp.statusCode());
        return resp.body();
    }

    private String actionJson(BridgeContext ctx, String action, String extra) {
        return "{" + kv("target_key", ctx.targetKey()) + "," + kv("action", action) +
                ",\"resource_id\":" + ctx.resourceId() + ",\"operation_id\":" + ctx.operationId() + ",\"exchange_id\":" + ctx.exchangeId() +
                (extra == null || extra.isBlank() ? "" : "," + extra) + "}";
    }

    private String postBridgeAction(BridgeContext ctx, String action, String extra) throws Exception {
        java.net.http.HttpResponse<String> resp = postJson("/api/bridge/action", actionJson(ctx, action, extra));
        if (resp.statusCode() < 200 || resp.statusCode() >= 300) throw new IllegalStateException("Negro action HTTP " + resp.statusCode() + ": " + resp.body());
        return resp.body();
    }

    private void openInNegro(HttpRequestResponse rr, String tool) {
        BridgeContext ctx = ingestContext(rr, tool);
        openBrowser(negroBaseUrl + ctx.webPath());
    }

    private void markInteresting(HttpRequestResponse rr, String tool) {
        BridgeContext ctx = ingestContext(rr, tool);
        try {
            postBridgeAction(ctx, "interesting", null);
            showMessage("Negro", "Resource marcado como Interesting y enlazado al exchange #" + ctx.exchangeId(), JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ex) { throw new IllegalStateException(ex); }
    }

    private void createFindingFromBurp(HttpRequestResponse rr, String tool) {
        BridgeContext ctx = ingestContext(rr, tool);
        HttpRequest request = rr.request();
        String path = "/";
        try { path = URI.create(request.url()).getRawPath(); } catch (Exception ignored) {}
        JTextField title = new JTextField(request.method() + " " + (path == null || path.isBlank() ? "/" : path), 34);
        JComboBox<String> severity = new JComboBox<>(new String[]{"info","low","medium","high","critical"});
        JTextArea description = new JTextArea(5, 34); description.setLineWrap(true); description.setWrapStyleWord(true);
        JPanel form = formPanel(); form.add(new JLabel("Título")); form.add(title); form.add(new JLabel("Severidad")); form.add(severity); form.add(new JLabel("Descripción / impacto observado")); form.add(new JScrollPane(description));
        int result = confirmDialog("Create Finding in Negro", form);
        if (result != JOptionPane.OK_OPTION) return;
        String t = title.getText().trim(); if (t.isEmpty()) return;
        String extra = kv("title", t) + "," + kv("severity", String.valueOf(severity.getSelectedItem())) + "," + kv("description", description.getText().trim());
        try {
            String body = postBridgeAction(ctx, "create_finding", extra);
            long fid = jsonLong(body, "finding_id");
            String web = jsonString(body, "web_path");
            showMessage("Negro", "Finding #" + fid + " creado con esta request/response como evidencia.", JOptionPane.INFORMATION_MESSAGE);
            if (web != null && askYesNo("Negro", "¿Abrir el Finding en Negro?")) openBrowser(negroBaseUrl + web);
        } catch (Exception ex) { throw new IllegalStateException(ex); }
    }

    private void attachFindingFromBurp(HttpRequestResponse rr, String tool) {
        BridgeContext ctx = ingestContext(rr, tool);
        FindingChoice finding = chooseFinding(ctx.targetKey(), "Attach to existing Finding"); if (finding == null) return;
        try {
            postBridgeAction(ctx, "attach_finding", "\"finding_id\":" + finding.id());
            showMessage("Negro", "Exchange #" + ctx.exchangeId() + " agregado a Finding #" + finding.id(), JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ex) { throw new IllegalStateException(ex); }
    }

    private void attachRetestFromBurp(HttpRequestResponse rr, String tool) {
        BridgeContext ctx = ingestContext(rr, tool);
        FindingChoice finding = chooseFinding(ctx.targetKey(), "Attach as Retest evidence"); if (finding == null) return;
        JComboBox<String> result = new JComboBox<>(new String[]{"still_vulnerable","fixed","fix_verified","inconclusive"});
        JTextArea notes = new JTextArea(4, 34); notes.setLineWrap(true); notes.setWrapStyleWord(true);
        JPanel form = formPanel(); form.add(new JLabel("Resultado")); form.add(result); form.add(new JLabel("Notas del retest")); form.add(new JScrollPane(notes));
        if (confirmDialog("Retest · Finding #" + finding.id(), form) != JOptionPane.OK_OPTION) return;
        String extra = "\"finding_id\":" + finding.id() + "," + kv("result", String.valueOf(result.getSelectedItem())) + "," + kv("notes", notes.getText().trim());
        try {
            postBridgeAction(ctx, "retest", extra);
            showMessage("Negro", "Retest registrado en Finding #" + finding.id() + " con exchange #" + ctx.exchangeId(), JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ex) { throw new IllegalStateException(ex); }
    }

    private List<FindingChoice> findings(String targetKey) {
        try {
            String json = getText("/api/bridge/findings/" + targetKey);
            List<FindingChoice> out = new ArrayList<>();
            Pattern p = Pattern.compile("\\{\\s*\\\"id\\\"\\s*:\\s*(\\d+).*?\\\"title\\\"\\s*:\\s*\\\"((?:\\\\.|[^\\\"\\\\])*)\\\".*?\\\"severity\\\"\\s*:\\s*\\\"((?:\\\\.|[^\\\"\\\\])*)\\\".*?\\\"status\\\"\\s*:\\s*\\\"((?:\\\\.|[^\\\"\\\\])*)\\\"", Pattern.DOTALL);
            Matcher m = p.matcher(json);
            while (m.find()) out.add(new FindingChoice(Long.parseLong(m.group(1)), unescapeJson(m.group(2)), unescapeJson(m.group(3)), unescapeJson(m.group(4))));
            return out;
        } catch (Exception ex) { throw new IllegalStateException(ex); }
    }

    private FindingChoice chooseFinding(String targetKey, String title) {
        List<FindingChoice> list = findings(targetKey);
        if (list.isEmpty()) { showMessage("Negro", "Este target todavía no tiene Findings.", JOptionPane.INFORMATION_MESSAGE); return null; }
        JComboBox<FindingChoice> combo = new JComboBox<>(list.toArray(new FindingChoice[0]));
        JPanel panel = formPanel(); panel.add(new JLabel("Finding")); panel.add(combo);
        return confirmDialog(title, panel) == JOptionPane.OK_OPTION ? (FindingChoice) combo.getSelectedItem() : null;
    }

    private JPanel formPanel() {
        JPanel panel = new JPanel(); panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS)); panel.setPreferredSize(new Dimension(430, panel.getPreferredSize().height)); return panel;
    }

    private int confirmDialog(String title, Component body) {
        final int[] result = {JOptionPane.CANCEL_OPTION};
        try {
            if (SwingUtilities.isEventDispatchThread()) return JOptionPane.showConfirmDialog(null, body, title, JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
            SwingUtilities.invokeAndWait(() -> result[0] = JOptionPane.showConfirmDialog(null, body, title, JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE));
        } catch (Exception ex) { throw new IllegalStateException(ex); }
        return result[0];
    }

    private boolean askYesNo(String title, String message) {
        final int[] result = {JOptionPane.NO_OPTION};
        try { SwingUtilities.invokeAndWait(() -> result[0] = JOptionPane.showConfirmDialog(null, message, title, JOptionPane.YES_NO_OPTION)); }
        catch (Exception ex) { return false; }
        return result[0] == JOptionPane.YES_OPTION;
    }

    private void showMessage(String title, String message, int type) {
        SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(null, message, title, type));
    }

    private void openBrowser(String url) {
        try {
            if (!Desktop.isDesktopSupported()) throw new IllegalStateException("Desktop API no disponible");
            Desktop.getDesktop().browse(URI.create(url));
        } catch (Exception ex) { throw new IllegalStateException("No se pudo abrir el navegador: " + ex.getMessage()); }
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
