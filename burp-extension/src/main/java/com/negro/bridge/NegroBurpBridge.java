package com.negro.bridge;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.*;
import javax.swing.event.MenuEvent;
import javax.swing.event.MenuListener;
import java.awt.*;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.Base64;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Negro Burp Bridge v0.29.0
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
    private JLabel lastErrorLabel;
    private Timer uiTimer;
    private volatile String lastErrorDetail = "";
    private volatile long lastSuccessfulContactMs = 0L;
    private final String bridgeInstanceId = UUID.randomUUID().toString();
    private final AtomicBoolean unloading = new AtomicBoolean(false);
    private final Set<String> runnerBridgeInFlight = ConcurrentHashMap.newKeySet();
    private final ScheduledExecutorService bridgePoller = Executors.newSingleThreadScheduledExecutor(r -> { Thread t = new Thread(r, "negro-repeater-bridge"); t.setDaemon(true); return t; });

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("Negro Burp Bridge");
        api.logging().logToOutput("Negro Burp Bridge v0.29.0 iniciado → " + negroBaseUrl + " · instance=" + bridgeInstanceId.substring(0, 8));
        api.extension().registerUnloadingHandler(() -> {
            if (unloading.compareAndSet(false, true)) {
                bridgePoller.shutdownNow();
                if (uiTimer != null) SwingUtilities.invokeLater(() -> uiTimer.stop());
                api.logging().logToOutput("Negro Burp Bridge descargado · poller detenido · instance=" + bridgeInstanceId.substring(0, 8));
            }
        });
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

        statusLabel = new JLabel("● Comprobando conexión…");
        panel.add(Box.createVerticalStrut(10));
        panel.add(statusLabel);
        panel.add(Box.createVerticalStrut(8));

        JLabel counters = new JLabel();
        panel.add(counters);
        lastErrorLabel = new JLabel(" ");
        lastErrorLabel.setFont(lastErrorLabel.getFont().deriveFont(11f));
        lastErrorLabel.setForeground(UIManager.getColor("Label.disabledForeground"));
        panel.add(lastErrorLabel);
        final int[] healthTicks = {0};
        uiTimer = new Timer(1000, e -> {
            counters.setText("Aceptados: " + accepted.get() + "   Fuera de scope: " + ignored.get() + "   Errores: " + errors.get());
            if (lastErrorLabel != null) {
                String detail = lastErrorDetail == null ? "" : lastErrorDetail;
                lastErrorLabel.setText(detail.isBlank() ? " " : "Último error: " + detail);
            }
            healthTicks[0]++;
            if (healthTicks[0] % 10 == 0) healthCheck();
        });
        uiTimer.start();
        panel.add(Box.createVerticalStrut(16));

        JPanel legend = new JPanel(new GridLayout(0, 2, 10, 8));
        legend.setBorder(BorderFactory.createTitledBorder("Estados en Burp"));
        legend.setAlignmentX(Component.LEFT_ALIGNMENT);
        legend.add(legendItem(new Color(102, 205, 225), "Signal Negro", "Automático · pendiente de revisión"));
        legend.add(legendItem(new Color(92, 145, 220), "Pendiente aprendizaje", "Aún no dominas la técnica"));
        legend.add(legendItem(new Color(225, 190, 80), "Revisar luego", "Mirado, sin conclusión"));
        legend.add(legendItem(new Color(232, 142, 72), "Interesante", "Hay evidencia para investigar"));
        legend.add(legendItem(new Color(180, 105, 215), "Correlacionar", "Falta otra pieza/flujo/identidad"));
        legend.add(legendItem(new Color(230, 82, 92), "Finding", "Confirmado por ti"));
        legend.add(legendItem(new Color(92, 176, 112), "Descartado", "Pruebas suficientes para cerrar"));
        panel.add(legend);
        panel.add(Box.createVerticalStrut(10));
        JLabel philosophy = new JLabel("Regla → Signal automático · Idea IA → Hipótesis humana · Runner = prueba explícita");
        philosophy.setFont(philosophy.getFont().deriveFont(Font.ITALIC));
        panel.add(philosophy);

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

    private JPanel legendItem(Color color, String title, String description) {
        JPanel row = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 3));
        JLabel swatch = new JLabel("   ");
        swatch.setOpaque(true);
        swatch.setPreferredSize(new Dimension(14, 24));
        swatch.setBackground(color);
        swatch.setBorder(BorderFactory.createLineBorder(color.darker()));

        JPanel copy = new JPanel();
        copy.setLayout(new BoxLayout(copy, BoxLayout.Y_AXIS));
        JLabel titleLabel = new JLabel(title);
        titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD));
        JLabel descriptionLabel = new JLabel(description);
        descriptionLabel.setFont(descriptionLabel.getFont().deriveFont(11f));
        descriptionLabel.setForeground(UIManager.getColor("Label.disabledForeground"));
        copy.add(titleLabel);
        copy.add(descriptionLabel);

        row.add(swatch);
        row.add(copy);
        return row;
    }

    private void markConnected(String detail) {
        lastSuccessfulContactMs = System.currentTimeMillis();
        SwingUtilities.invokeLater(() -> {
            if (statusLabel != null) statusLabel.setText("● Conectado a Negro" + (detail == null || detail.isBlank() ? "" : " · " + detail));
        });
    }

    private void markUnavailable(Throwable ex) {
        // Do not paint a false offline state if traffic was successfully ingested
        // moments ago (for example when the first health check raced app startup).
        if (System.currentTimeMillis() - lastSuccessfulContactMs < 5000L) return;
        SwingUtilities.invokeLater(() -> {
            if (statusLabel != null) statusLabel.setText("○ Negro no disponible · " + ex.getClass().getSimpleName());
        });
    }

    private void healthCheck() {
        java.net.http.HttpRequest req = java.net.http.HttpRequest.newBuilder()
                .uri(URI.create(negroBaseUrl + "/api/ingest/health"))
                .timeout(Duration.ofSeconds(10))
                .GET().build();
        client.sendAsync(req, BodyHandlers.ofString())
                .thenAccept(r -> {
                    if (r.statusCode() == 200) markConnected("health OK");
                    else SwingUtilities.invokeLater(() -> { if (statusLabel != null) statusLabel.setText("○ Negro respondió HTTP " + r.statusCode()); });
                })
                .exceptionally(ex -> {
                    markUnavailable(ex);
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
                    return ResponseReceivedAction.continueWith(response, response.annotations());
                }
                String tool = response.toolSource().toolType().name();
                String runnerKey = request.method().toUpperCase() + " " + request.url();
                if ("EXTENSIONS".equalsIgnoreCase(tool) && runnerBridgeInFlight.contains(runnerKey)) {
                    return ResponseReceivedAction.continueWith(response, response.annotations());
                }
                String json = toJson(request, response, tool);
                sendAsync(json, request.method(), request.url(), tool, response.annotations());
            } catch (Exception ex) {
                recordError("Bridge: " + (ex.getMessage() == null ? ex.getClass().getSimpleName() : ex.getMessage()));
                api.logging().logToError("Negro Bridge: " + ex.getMessage());
            }
            return ResponseReceivedAction.continueWith(response, response.annotations());
        }
    }

    private void pollRepeaterQueue() {
        if (unloading.get()) return;
        try {
            java.net.http.HttpRequest req = java.net.http.HttpRequest.newBuilder()
                    .uri(URI.create(negroBaseUrl + "/api/bridge/repeater/next"))
                    .timeout(Duration.ofSeconds(10))
                    .header("Accept", "application/json")
                    .header("X-Negro-Bridge-Id", bridgeInstanceId)
                    .header("X-Negro-Bridge-Version", "0.29.0")
                    .GET().build();

            // Use a synchronous call on the dedicated poller thread. In v0.16.2 an
            // unobserved CompletableFuture failure could claim a queue item server-side
            // without ever running the thenAccept callback, leaving the item stuck in
            // "claimed" and producing no Burp logs. Blocking here is safe because this
            // method already runs on a single daemon ScheduledExecutorService.
            java.net.http.HttpResponse<String> resp = client.send(req, BodyHandlers.ofString(StandardCharsets.UTF_8));
            String body = resp.body() == null ? "" : resp.body();
            boolean pending = jsonBoolean(body, "pending", false);
            if (resp.statusCode() != 200 || pending || jsonBoolean(body, "upgrade_required", false)) {
                api.logging().logToOutput("Negro → Bridge poll: HTTP " + resp.statusCode() + " · body=" + body.length() + " chars · pending=" + pending + " · instance=" + bridgeInstanceId.substring(0, 8));
            }
            if (resp.statusCode() != 200 || !pending) return;

            api.logging().logToOutput("Negro → Repeater: item pendiente recibido del backend");
            String targetKey = jsonString(body, "target_key");
            String url = jsonString(body, "url");
            String method = jsonString(body, "method");
            String caption = jsonString(body, "caption");
            String requestB64 = jsonString(body, "request_b64");
            String jobKind = jsonString(body, "job_kind");
            if (jobKind == null || jobKind.isBlank()) jobKind = "repeater";
            long queueId = jsonLong(body, "id");
            api.logging().logToOutput("Negro → Bridge claim: queue=" + queueId + " kind=" + jobKind + " target=" + targetKey + " method=" + method + " url=" + url + " b64chars=" + (requestB64 == null ? 0 : requestB64.length()));
            boolean ok = false;
            String error = "";
            String resultRequestB64 = "";
            String responseB64 = "";
            String responseBodyB64 = "";
            String responseHeadersJson = "[]";
            Integer statusCode = null;
            String resultUrl = url == null ? "" : url;
            long elapsedMs = 0L;
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
                    byte[] replayRaw = normalizeRawRequestForRepeater(raw);
                    normalizedHttp2 = replayRaw != raw;
                    request = HttpRequest.httpRequest(service, ByteArray.byteArray(replayRaw));
                    if (request.toByteArray().length() == 0 || request.method() == null || request.method().isBlank()) {
                        api.logging().logToError("Negro → Bridge: request reconstruida vacía; usando fallback URL. queue=" + queueId + " raw=" + rawLength + "B");
                        request = fallbackRequest(url, method, service);
                    }
                } else {
                    request = fallbackRequest(url, method, service);
                }

                if ("execute".equalsIgnoreCase(jobKind) || "replay_execute".equalsIgnoreCase(jobKind)) {
                    String inflightKey = request.method().toUpperCase() + " " + request.url();
                    runnerBridgeInFlight.add(inflightKey);
                    long startedNs = System.nanoTime();
                    try {
                        HttpRequestResponse pair = api.http().sendRequest(request);
                        elapsedMs = Math.max(0L, (System.nanoTime() - startedNs) / 1_000_000L);
                        if (pair == null || !pair.hasResponse() || pair.response() == null) {
                            throw new IllegalStateException("Burp no recibió una Response del target");
                        }
                        HttpRequest sent = pair.request() == null ? request : pair.request();
                        HttpResponse received = pair.response();
                        resultRequestB64 = Base64.getEncoder().encodeToString(sent.toByteArray().getBytes());
                        responseB64 = Base64.getEncoder().encodeToString(received.toByteArray().getBytes());
                        responseBodyB64 = Base64.getEncoder().encodeToString(received.body().getBytes());
                        responseHeadersJson = headersJson(received.headers());
                        statusCode = (int) received.statusCode();
                        resultUrl = sent.url();
                        ok = true;
                        api.logging().logToOutput(("replay_execute".equalsIgnoreCase(jobKind) ? "Negro Replay" : "Negro Runner") + " ✓ Burp transport · queue=" + queueId + " HTTP " + statusCode + " · " + elapsedMs + "ms · " + sent.method() + " " + sent.url());
                    } finally {
                        runnerBridgeInFlight.remove(inflightKey);
                    }
                } else {
                    String tabName = caption == null || caption.isBlank() ? "Negro · " + (method == null ? "GET" : method) : caption;
                    api.repeater().sendToRepeater(request, tabName);
                    ok = true;
                    api.logging().logToOutput("Negro → Repeater: queue=" + queueId + " raw=" + rawLength + "B reconstructed=" + request.toByteArray().length() + "B h2_normalized=" + normalizedHttp2 + " · " + request.method() + " " + request.url());
                }
            } catch (Throwable ex) {
                error = ex.getMessage() == null ? ex.getClass().getSimpleName() : ex.getMessage();
                api.logging().logToError("Negro → Bridge falló: " + ex.getClass().getSimpleName() + ": " + error);
            }
            ackBridge(targetKey, queueId, ok, error, resultRequestB64, responseB64, responseBodyB64, responseHeadersJson, statusCode, resultUrl, elapsedMs);
        } catch (Throwable ex) {
            String msg = ex.getMessage() == null ? ex.getClass().getSimpleName() : ex.getMessage();
            api.logging().logToError("Negro → Repeater poll falló: " + ex.getClass().getSimpleName() + ": " + msg);
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

    private void ackBridge(String targetKey, long queueId, boolean ok, String error,
                           String requestB64, String responseB64, String responseBodyB64,
                           String responseHeadersJson, Integer statusCode, String resultUrl, long elapsedMs) {
        if (targetKey == null || queueId <= 0) return;
        String json = "{" +
                "\"ok\":" + ok + "," +
                kv("error", error == null ? "" : error) + "," +
                kv("request_b64", requestB64 == null ? "" : requestB64) + "," +
                kv("response_b64", responseB64 == null ? "" : responseB64) + "," +
                kv("response_body_b64", responseBodyB64 == null ? "" : responseBodyB64) + "," +
                "\"response_headers\":" + (responseHeadersJson == null || responseHeadersJson.isBlank() ? "[]" : responseHeadersJson) + "," +
                "\"status_code\":" + (statusCode == null ? "null" : statusCode.toString()) + "," +
                kv("url", resultUrl == null ? "" : resultUrl) + "," +
                "\"elapsed_ms\":" + Math.max(0L, elapsedMs) +
                "}";
        java.net.http.HttpRequest req = java.net.http.HttpRequest.newBuilder()
                .uri(URI.create(negroBaseUrl + "/api/bridge/repeater/" + targetKey + "/" + queueId + "/ack"))
                .timeout(Duration.ofSeconds(10)).header("Content-Type", "application/json")
                .POST(BodyPublishers.ofString(json, StandardCharsets.UTF_8)).build();
        client.sendAsync(req, BodyHandlers.discarding());
    }

    /**
     * Tiny flat-JSON reader used by the local bridge protocol.
     *
     * Avoid recursive regexes for JSON strings here: request_b64 can be several
     * kilobytes or more. Java's regex engine may recurse once per character and
     * throw StackOverflowError; ScheduledExecutorService then suppresses future
     * poll executions, which looks exactly like the bridge "freezing" after
     * pending=true.
     */
    private int jsonValueStart(String json, String key) {
        if (json == null || key == null) return -1;
        String needle = "\"" + key + "\"";
        int from = 0;
        while (true) {
            int keyPos = json.indexOf(needle, from);
            if (keyPos < 0) return -1;
            int i = keyPos + needle.length();
            while (i < json.length() && Character.isWhitespace(json.charAt(i))) i++;
            if (i < json.length() && json.charAt(i) == ':') {
                i++;
                while (i < json.length() && Character.isWhitespace(json.charAt(i))) i++;
                return i;
            }
            from = keyPos + needle.length();
        }
    }

    private String jsonString(String json, String key) {
        int i = jsonValueStart(json, key);
        if (i < 0 || i >= json.length()) return null;
        if (json.startsWith("null", i)) return null;
        if (json.charAt(i) != '"') return null;
        i++;
        StringBuilder out = new StringBuilder();
        while (i < json.length()) {
            char c = json.charAt(i++);
            if (c == '"') return out.toString();
            if (c != '\\') {
                out.append(c);
                continue;
            }
            if (i >= json.length()) return null;
            char esc = json.charAt(i++);
            switch (esc) {
                case '"' -> out.append('"');
                case '\\' -> out.append('\\');
                case '/' -> out.append('/');
                case 'b' -> out.append('\b');
                case 'f' -> out.append('\f');
                case 'n' -> out.append('\n');
                case 'r' -> out.append('\r');
                case 't' -> out.append('\t');
                case 'u' -> {
                    if (i + 4 > json.length()) return null;
                    try {
                        out.append((char) Integer.parseInt(json.substring(i, i + 4), 16));
                    } catch (NumberFormatException ex) {
                        return null;
                    }
                    i += 4;
                }
                default -> out.append(esc);
            }
        }
        return null;
    }

    private String unescapeJson(String value) {
        if (value == null) return null;
        StringBuilder out = new StringBuilder(value.length());
        int i = 0;
        while (i < value.length()) {
            char c = value.charAt(i++);
            if (c != '\\') {
                out.append(c);
                continue;
            }
            if (i >= value.length()) {
                out.append('\\');
                break;
            }
            char esc = value.charAt(i++);
            switch (esc) {
                case '"' -> out.append('"');
                case '\\' -> out.append('\\');
                case '/' -> out.append('/');
                case 'b' -> out.append('\b');
                case 'f' -> out.append('\f');
                case 'n' -> out.append('\n');
                case 'r' -> out.append('\r');
                case 't' -> out.append('\t');
                case 'u' -> {
                    if (i + 4 <= value.length()) {
                        try {
                            out.append((char) Integer.parseInt(value.substring(i, i + 4), 16));
                            i += 4;
                        } catch (NumberFormatException ex) {
                            out.append("\\u");
                        }
                    } else {
                        out.append("\\u");
                    }
                }
                default -> {
                    out.append('\\');
                    out.append(esc);
                }
            }
        }
        return out.toString();
    }

    private long jsonLong(String json, String key) {
        int i = jsonValueStart(json, key);
        if (i < 0 || i >= json.length()) return -1;
        int start = i;
        if (json.charAt(i) == '-') i++;
        while (i < json.length() && Character.isDigit(json.charAt(i))) i++;
        if (i == start || (i == start + 1 && json.charAt(start) == '-')) return -1;
        try {
            return Long.parseLong(json.substring(start, i));
        } catch (NumberFormatException ex) {
            return -1;
        }
    }

    private boolean jsonBoolean(String json, String key, boolean defaultValue) {
        int i = jsonValueStart(json, key);
        if (i < 0) return defaultValue;
        if (json.startsWith("true", i)) return true;
        if (json.startsWith("false", i)) return false;
        return defaultValue;
    }

    private void sendAsync(String json, String method, String observedUrl, String tool, Annotations annotations) {
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
                            markConnected("ingest OK");
                            long signalCount = jsonLong(body, "signal_count");
                            long investigationCount = Math.max(0, jsonLong(body, "investigation_count"));
                            long hypothesisCount = Math.max(0, jsonLong(body, "hypothesis_count"));
                            long contextMatchCount = Math.max(0, jsonLong(body, "context_match_count"));
                            long findingCount = Math.max(0, jsonLong(body, "finding_count"));
                            String requestHash = jsonString(body, "request_hash");
                            String responseHash = jsonString(body, "response_hash");
                            if (signalCount > 0) {
                                // HttpHandler annotations are reliable while the handler is returning,
                                // but this callback runs asynchronously after that lifecycle. Mutating
                                // response.annotations() here does not reliably repaint Proxy history.
                                // Re-bind the result to the actual ProxyHttpRequestResponse by exact
                                // persisted hashes and annotate THAT history item instead.
                                if ("PROXY".equalsIgnoreCase(tool)) {
                                    scheduleSignalAnnotation(method, observedUrl, requestHash, responseHash, signalCount, 0);
                                } else if (annotations != null) {
                                    try {
                                        annotations.setHighlightColor(HighlightColor.CYAN);
                                        appendNegroNote(annotations, "NEGRO · 🩵 SIGNAL · " + signalCount + " indicio(s) automático(s) sin revisar");
                                    } catch (Exception ignored) {}
                                }
                            }
                            if (investigationCount + hypothesisCount + contextMatchCount + findingCount > 0) {
                                String contextLine = "NEGRO · CONTEXTO · INV " + investigationCount + " · HYP " + hypothesisCount + " · CTX " + contextMatchCount + " · FIND " + findingCount;
                                if ("PROXY".equalsIgnoreCase(tool)) scheduleContextAnnotation(method, observedUrl, requestHash, responseHash, contextLine, 0);
                                else if (annotations != null) setNegroContextNote(annotations, contextLine);
                            }
                            api.logging().logToOutput("Negro ← ingest HTTP " + resp.statusCode() + " accepted=true · signals=" + Math.max(0, signalCount) + " · inv=" + investigationCount + " hyp=" + hypothesisCount + " ctx=" + contextMatchCount + " find=" + findingCount);
                        } else {
                            ignored.incrementAndGet();
                            api.logging().logToOutput("Negro ← ingest HTTP " + resp.statusCode() + " accepted=false");
                        }
                    } else {
                        recordError("Ingest HTTP " + resp.statusCode());
                        api.logging().logToError("Negro ingest HTTP " + resp.statusCode() + ": " + body);
                    }
                })
                .exceptionally(ex -> {
                    recordError("Ingest " + ex.getClass().getSimpleName() + (ex.getMessage() == null ? "" : ": " + ex.getMessage()));
                    api.logging().logToError("Negro ingest exception: " + ex.getClass().getSimpleName() + ": " + (ex.getMessage() == null ? "" : ex.getMessage()));
                    return null;
                });
    }

    private void recordError(String detail) {
        errors.incrementAndGet();
        String clean = detail == null ? "desconocido" : detail.replace('\n', ' ').replace('\r', ' ').trim();
        lastErrorDetail = clean.length() > 180 ? clean.substring(0, 180) + "…" : clean;
    }

    private String sha256(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(data == null ? new byte[0] : data);
            StringBuilder out = new StringBuilder(digest.length * 2);
            for (byte b : digest) out.append(String.format("%02x", b & 0xff));
            return out.toString();
        } catch (Exception ex) {
            throw new IllegalStateException("SHA-256 no disponible", ex);
        }
    }

    private void scheduleSignalAnnotation(String method, String observedUrl, String requestHash, String responseHash, long signalCount, int attempt) {
        if (unloading.get() || signalCount <= 0 || requestHash == null || requestHash.isBlank()) return;
        long delayMs = switch (attempt) {
            case 0 -> 120L;
            case 1 -> 450L;
            default -> 1000L;
        };
        bridgePoller.schedule(() -> {
            if (unloading.get()) return;
            boolean matched = applySignalAnnotationToProxyHistory(method, observedUrl, requestHash, responseHash, signalCount);
            if (!matched && attempt < 2) {
                scheduleSignalAnnotation(method, observedUrl, requestHash, responseHash, signalCount, attempt + 1);
            } else if (!matched) {
                api.logging().logToError("Negro signal sync: no encontré el item exacto en Proxy history · " + method + " " + observedUrl);
            }
        }, delayMs, TimeUnit.MILLISECONDS);
    }

    private boolean applySignalAnnotationToProxyHistory(String method, String observedUrl, String requestHash, String responseHash, long signalCount) {
        try {
            List<ProxyHttpRequestResponse> candidates = api.proxy().history(item -> {
                try {
                    if (!item.hasResponse()) return false;
                    HttpRequest req = item.finalRequest();
                    return method.equalsIgnoreCase(req.method()) && observedUrl.equals(req.url());
                } catch (Exception ignored) {
                    return false;
                }
            });

            int checked = 0;
            for (int i = candidates.size() - 1; i >= 0 && checked < 30; i--, checked++) {
                ProxyHttpRequestResponse item = candidates.get(i);
                String reqHash = sha256(item.finalRequest().toByteArray().getBytes());
                if (!requestHash.equalsIgnoreCase(reqHash)) continue;
                if (responseHash != null && !responseHash.isBlank()) {
                    String respHash = sha256(item.response().toByteArray().getBytes());
                    if (!responseHash.equalsIgnoreCase(respHash)) continue;
                }

                Annotations a = item.annotations();
                // An automatic Signal must never erase a human decision or a manual
                // highlight. Cyan is only the default for an unreviewed observation.
                if (!a.hasHighlightColor() || a.highlightColor() == HighlightColor.NONE || a.highlightColor() == HighlightColor.CYAN) {
                    a.setHighlightColor(HighlightColor.CYAN);
                }
                appendNegroNote(a, "NEGRO · 🩵 SIGNAL · " + signalCount + " indicio(s) automático(s) sin revisar");
                api.logging().logToOutput("Negro ✓ Proxy history cyan · #" + item.id() + " · signals=" + signalCount + " · " + method + " " + observedUrl);
                return true;
            }
            return false;
        } catch (Exception ex) {
            recordError("Signal sync: " + (ex.getMessage() == null ? ex.getClass().getSimpleName() : ex.getMessage()));
            api.logging().logToError("Negro signal sync exception: " + ex.getClass().getSimpleName() + ": " + (ex.getMessage() == null ? "" : ex.getMessage()));
            return false;
        }
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

    private record IdentityChoice(long identityId, long contextId, String label) {
        @Override public String toString() { return label; }
    }

    private record ReplayMenuData(BridgeContext context, List<IdentityChoice> identities) {}

    private record FlowChoice(long id, String name, String captureStatus) {
        @Override public String toString() { return "#" + id + " · " + name + ("capturing".equals(captureStatus) ? " · ● capturando" : ""); }
    }

    private record AuthMaterialChoice(String fingerprint, String type, String name, String preview) {
        @Override public String toString() { return type + " · " + name + " · " + preview; }
    }

    private record InvestigationChoice(long id, String title, String status) {
        @Override public String toString() { return id <= 0 ? title : "#" + id + " · " + title + (status == null || status.isBlank() ? "" : " · " + status); }
    }

    private record HypothesisChoice(long id, String title, String status) {
        @Override public String toString() { return "#" + id + " · " + title + (status == null || status.isBlank() ? "" : " · " + status); }
    }

    private record ParameterChoice(long id, String name, String normalizedName, String value, String location) {
        @Override public String toString() {
            String key = normalizedName == null || normalizedName.isBlank() ? name : normalizedName;
            String preview = value == null ? "" : value;
            if (preview.length() > 72) preview = preview.substring(0, 69) + "…";
            return key + " = " + preview + (location == null || location.isBlank() ? "" : " · " + location);
        }
    }

    private record WatchTargetChoice(String kind, long id, String label) {
        @Override public String toString() { return ("hypothesis".equals(kind) ? "HYP" : "INV") + " · " + label; }
    }

    private final class NegroContextMenu implements ContextMenuItemsProvider {
        @Override
        public List<Component> provideMenuItems(ContextMenuEvent event) {
            List<HttpRequestResponse> selected = selectedRequestResponses(event);
            if (selected.isEmpty() || selected.get(0).request() == null || isNegroBridgeTraffic(selected.get(0).request().url())) return List.of();
            String selectedText = selectedEditorText(event);
            JMenu menu = new JMenu("Negro");
            JMenuItem open = new JMenuItem("Abrir en Negro");

            // Replay is intentionally manual.  The submenu is populated lazily so
            // opening a normal Burp context menu never blocks on Negro.  Selecting
            // an Identity prepares a reviewable request in Negro; it does NOT send it.
            JMenu replayMenu = new JMenu("Replay as Identity");
            JMenuItem replayLoading = new JMenuItem("Abrir para cargar Identity Contexts…");
            replayLoading.setEnabled(false);
            replayMenu.add(replayLoading);
            JMenuItem compareIdentity = new JMenuItem("Compare Identity…");

            JMenu contextMenu = new JMenu("Contexto");
            JMenuItem invAttach = new JMenuItem("Añadir a Investigation…");
            JMenuItem invCreate = new JMenuItem("Crear Investigation desde esta Request…");
            JMenuItem hypCreate = new JMenuItem("Crear Hypothesis…");
            JMenuItem hypAttach = new JMenuItem("Adjuntar a Hypothesis…");
            JMenuItem entityCreate = new JMenuItem("Crear Entity desde key/valor…");
            JMenuItem followValue = new JMenuItem("Seguir key / valor…");
            JMenuItem watch = new JMenuItem("Watch de key / valor…");
            JMenuItem note = new JMenuItem("Agregar nota…");
            contextMenu.add(invAttach); contextMenu.add(invCreate); contextMenu.addSeparator();
            contextMenu.add(hypCreate); contextMenu.add(hypAttach); contextMenu.addSeparator();
            contextMenu.add(entityCreate); contextMenu.add(followValue); contextMenu.add(watch); contextMenu.addSeparator(); contextMenu.add(note);

            JMenu stateMenu = new JMenu("Estado");
            addStateItem(stateMenu, event, "🔵 Pendiente aprendizaje", "learning");
            addStateItem(stateMenu, event, "🟡 Revisar luego", "review_later");
            addStateItem(stateMenu, event, "🟠 Interesante", "interesting");
            addStateItem(stateMenu, event, "🟣 Correlacionar", "correlate");
            addStateItem(stateMenu, event, "🔴 Finding", "finding");
            addStateItem(stateMenu, event, "🟢 Descartado", "discarded");
            addStateItem(stateMenu, event, "⚪ Normal", "normal");

            JMenu flowMenu = new JMenu("Flow");
            JMenuItem flowStart = new JMenuItem("Iniciar Flow desde aquí…");
            JMenuItem flowAdd = new JMenuItem("Añadir al Flow actual…");
            JMenuItem flowEnd = new JMenuItem("Terminar Flow aquí…");
            JMenuItem flowSelected = new JMenuItem("Crear Flow con Requests seleccionadas…");
            flowMenu.add(flowStart); flowMenu.add(flowAdd); flowMenu.add(flowEnd); flowMenu.addSeparator(); flowMenu.add(flowSelected);

            JMenu identityMenu = new JMenu("Identidad");
            JMenuItem assignIdentity = new JMenuItem("Asignar a Identity…");
            JMenuItem createIdentity = new JMenuItem("Crear Identity desde esta Request…");
            JMenuItem updateAuth = new JMenuItem("Actualizar auth de Identity…");
            JMenuItem sendAs = new JMenuItem("Enviar a Repeater con Identity…");
            identityMenu.add(assignIdentity); identityMenu.add(createIdentity); identityMenu.add(updateAuth); identityMenu.addSeparator(); identityMenu.add(sendAs);

            JMenu findingMenu = new JMenu("Finding");
            JMenuItem createFinding = new JMenuItem("Crear Finding…");
            JMenuItem attachFinding = new JMenuItem("Adjuntar a Finding existente…");
            JMenuItem retest = new JMenuItem("Adjuntar como evidencia de Retest…");
            findingMenu.add(createFinding); findingMenu.add(attachFinding); findingMenu.addSeparator(); findingMenu.add(retest);

            String tool = event.toolType() == null ? "OTHER" : event.toolType().name();
            replayMenu.addMenuListener(new MenuListener() {
                private boolean loading = false;
                @Override public void menuSelected(MenuEvent event) {
                    if (loading || Boolean.TRUE.equals(replayMenu.getClientProperty("negro.loaded"))) return;
                    loading = true;
                    replayMenu.removeAll();
                    JMenuItem wait = new JMenuItem("Cargando Identity Contexts…"); wait.setEnabled(false); replayMenu.add(wait);
                    new SwingWorker<ReplayMenuData, Void>() {
                        @Override protected ReplayMenuData doInBackground() {
                            BridgeContext ctx = ingestContext(selected.get(0), tool);
                            return new ReplayMenuData(ctx, identityChoices(ctx.targetKey()));
                        }
                        @Override protected void done() {
                            replayMenu.removeAll();
                            try {
                                ReplayMenuData data = get();
                                JMenuItem anonymous = new JMenuItem("Sin autenticación");
                                anonymous.addActionListener(e -> runContextAction("replay-anonymous", () -> prepareReplayFromContext(selected.get(0), data.context(), new IdentityChoice(0,0,"Sin autenticación"))));
                                replayMenu.add(anonymous);
                                if (!data.identities().isEmpty()) replayMenu.addSeparator();
                                for (IdentityChoice choice : data.identities()) {
                                    JMenuItem item = new JMenuItem(choice.label());
                                    item.addActionListener(e -> runContextAction("replay-identity", () -> prepareReplayFromContext(selected.get(0), data.context(), choice)));
                                    replayMenu.add(item);
                                }
                                replayMenu.addSeparator();
                                JMenuItem choose = new JMenuItem("Elegir / comparar…");
                                choose.addActionListener(e -> runContextAction("replay-compare", () -> openReplayChooserFromContext(data.context())));
                                replayMenu.add(choose);
                                replayMenu.putClientProperty("negro.loaded", Boolean.TRUE);
                                replayMenu.revalidate(); replayMenu.repaint();
                            } catch (Exception ex) {
                                JMenuItem error = new JMenuItem("No se pudieron cargar Identity Contexts"); error.setEnabled(false); replayMenu.add(error);
                                replayMenu.revalidate(); replayMenu.repaint();
                                recordError("Replay menu: " + ex.getMessage());
                            } finally { loading = false; }
                        }
                    }.execute();
                }
                @Override public void menuDeselected(MenuEvent event) {}
                @Override public void menuCanceled(MenuEvent event) {}
            });
            open.addActionListener(e -> runContextAction("open", () -> openInNegro(selected.get(0), tool)));
            invAttach.addActionListener(e -> runContextAction("inv-attach", () -> attachInvestigationFromBurp(selected.get(0), tool)));
            invCreate.addActionListener(e -> runContextAction("inv-create", () -> createInvestigationFromBurp(selected.get(0), tool)));
            hypCreate.addActionListener(e -> runContextAction("hyp-create", () -> createHypothesisFromBurp(selected.get(0), tool)));
            hypAttach.addActionListener(e -> runContextAction("hyp-attach", () -> attachHypothesisFromBurp(selected.get(0), tool)));
            entityCreate.addActionListener(e -> runContextAction("entity-create", () -> createEntityFromBurp(selected.get(0), tool, selectedText)));
            followValue.addActionListener(e -> runContextAction("follow", () -> followValueFromBurp(selected.get(0), tool, selectedText)));
            watch.addActionListener(e -> runContextAction("watch", () -> createWatchFromBurp(selected.get(0), tool, selectedText)));
            note.addActionListener(e -> runContextAction("note", () -> addNoteFromBurp(selected, tool)));
            flowStart.addActionListener(e -> runContextAction("flow-start", () -> startFlowFromBurp(selected.get(0), tool)));
            flowAdd.addActionListener(e -> runContextAction("flow-add", () -> addToFlowFromBurp(selected.get(0), tool)));
            flowEnd.addActionListener(e -> runContextAction("flow-end", () -> endFlowFromBurp(selected.get(0), tool)));
            flowSelected.addActionListener(e -> runContextAction("flow-selected", () -> createFlowFromSelection(selected, tool)));
            assignIdentity.addActionListener(e -> runContextAction("identity-assign", () -> assignIdentityFromBurp(selected.get(0), tool)));
            createIdentity.addActionListener(e -> runContextAction("identity-create", () -> createIdentityFromBurp(selected.get(0), tool)));
            updateAuth.addActionListener(e -> runContextAction("identity-update", () -> updateIdentityAuthFromBurp(selected.get(0), tool)));
            sendAs.addActionListener(e -> runContextAction("identity-send", () -> sendAsIdentityFromBurp(selected.get(0), tool)));
            compareIdentity.addActionListener(e -> runContextAction("replay-compare", () -> openReplayChooserFromBurp(selected.get(0), tool)));
            createFinding.addActionListener(e -> runContextAction("finding", () -> createFindingFromBurp(selected.get(0), tool)));
            attachFinding.addActionListener(e -> runContextAction("attach", () -> attachFindingFromBurp(selected.get(0), tool)));
            retest.addActionListener(e -> runContextAction("retest", () -> attachRetestFromBurp(selected.get(0), tool)));
            menu.add(open); menu.add(replayMenu); menu.add(compareIdentity); menu.addSeparator(); menu.add(contextMenu); menu.add(flowMenu); menu.add(identityMenu); menu.add(stateMenu); menu.add(findingMenu);
            return List.of(menu);
        }
    }

    private void addStateItem(JMenu stateMenu, ContextMenuEvent event, String label, String state) {
        JMenuItem item = new JMenuItem(label);
        item.addActionListener(e -> runContextAction("state-" + state, () -> setStateFromBurp(selectedRequestResponses(event), event.toolType() == null ? "OTHER" : event.toolType().name(), state)));
        stateMenu.add(item);
    }

    private String selectedEditorText(ContextMenuEvent event) {
        try {
            var editorOpt = event.messageEditorRequestResponse();
            if (editorOpt.isEmpty()) return "";
            var editor = editorOpt.get();
            var offsetsOpt = editor.selectionOffsets();
            if (offsetsOpt.isEmpty()) return "";
            var range = offsetsOpt.get();
            byte[] bytes;
            String context = editor.selectionContext().name();
            HttpRequestResponse rr = editor.requestResponse();
            if ("RESPONSE".equals(context) && rr.hasResponse() && rr.response() != null) bytes = rr.response().toByteArray().getBytes();
            else bytes = rr.request().toByteArray().getBytes();
            int start = Math.max(0, Math.min(range.startIndexInclusive(), bytes.length));
            int end = Math.max(start, Math.min(range.endIndexExclusive(), bytes.length));
            String value = new String(bytes, start, end - start, StandardCharsets.UTF_8).trim();
            if (value.length() > 1000) value = value.substring(0, 1000);
            if (value.length() >= 2 && ((value.startsWith("\"") && value.endsWith("\"")) || (value.startsWith("'") && value.endsWith("'")))) value = value.substring(1, value.length() - 1);
            return value.trim();
        } catch (Exception ex) {
            return "";
        }
    }

    private List<HttpRequestResponse> selectedRequestResponses(ContextMenuEvent event) {
        List<HttpRequestResponse> selected = event.selectedRequestResponses();
        if (selected != null && !selected.isEmpty()) return selected;
        return event.messageEditorRequestResponse().map(x -> List.of(x.requestResponse())).orElse(List.of());
    }

    private HttpRequestResponse selectedRequestResponse(ContextMenuEvent event) {
        List<HttpRequestResponse> selected = selectedRequestResponses(event);
        return selected.isEmpty() ? null : selected.get(0);
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
            // A context-menu action re-syncs an already observed Burp item so Negro
            // can resolve its exchange_id. It must not count as a new Flow occurrence.
            if (payload.endsWith("}")) payload = payload.substring(0, payload.length() - 1) + ",\"context_sync\":true}";
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

    private HighlightColor stateColor(String state) {
        return switch (state) {
            case "learning" -> HighlightColor.BLUE;
            case "review_later" -> HighlightColor.YELLOW;
            case "interesting" -> HighlightColor.ORANGE;
            case "correlate" -> HighlightColor.MAGENTA;
            case "finding" -> HighlightColor.RED;
            case "discarded" -> HighlightColor.GREEN;
            default -> HighlightColor.NONE;
        };
    }

    private String stateLabel(String state) {
        return switch (state) {
            case "learning" -> "🔵 PENDIENTE APRENDIZAJE";
            case "review_later" -> "🟡 REVISAR LUEGO";
            case "interesting" -> "🟠 INTERESANTE";
            case "correlate" -> "🟣 CORRELACIONAR";
            case "finding" -> "🔴 FINDING";
            case "discarded" -> "🟢 DESCARTADO";
            default -> "⚪ NORMAL";
        };
    }

    private void appendNegroNote(Annotations annotations, String line) {
        if (annotations == null || line == null || line.isBlank()) return;
        String current = annotations.hasNotes() ? annotations.notes() : "";
        // Keep one current NEGRO state/signal line readable without destroying the hunter's own Burp notes.
        if (current.contains(line)) return;
        String next = current == null || current.isBlank() ? line : current + "\n" + line;
        annotations.setNotes(next);
    }

    private void setNegroContextNote(Annotations annotations, String line) {
        if (annotations == null || line == null || line.isBlank()) return;
        String current = annotations.hasNotes() ? annotations.notes() : "";
        List<String> keep = new ArrayList<>();
        if (current != null && !current.isBlank()) {
            for (String part : current.split("\\R")) if (!part.startsWith("NEGRO · CONTEXTO ·")) keep.add(part);
        }
        keep.add(line);
        annotations.setNotes(String.join("\n", keep));
    }

    private void scheduleContextAnnotation(String method, String observedUrl, String requestHash, String responseHash, String contextLine, int attempt) {
        if (unloading.get() || requestHash == null || requestHash.isBlank() || contextLine == null || contextLine.isBlank()) return;
        long delayMs = switch (attempt) { case 0 -> 160L; case 1 -> 500L; default -> 1100L; };
        bridgePoller.schedule(() -> {
            if (unloading.get()) return;
            boolean matched = applyContextAnnotationToProxyHistory(method, observedUrl, requestHash, responseHash, contextLine);
            if (!matched && attempt < 2) scheduleContextAnnotation(method, observedUrl, requestHash, responseHash, contextLine, attempt + 1);
        }, delayMs, TimeUnit.MILLISECONDS);
    }

    private boolean applyContextAnnotationToProxyHistory(String method, String observedUrl, String requestHash, String responseHash, String contextLine) {
        try {
            List<ProxyHttpRequestResponse> candidates = api.proxy().history(item -> {
                try { return item.hasResponse() && method.equalsIgnoreCase(item.finalRequest().method()) && observedUrl.equals(item.finalRequest().url()); }
                catch (Exception ignored) { return false; }
            });
            int checked = 0;
            for (int i = candidates.size() - 1; i >= 0 && checked < 30; i--, checked++) {
                ProxyHttpRequestResponse item = candidates.get(i);
                String reqHash = sha256(item.finalRequest().toByteArray().getBytes());
                if (!requestHash.equalsIgnoreCase(reqHash)) continue;
                if (responseHash != null && !responseHash.isBlank()) {
                    String respHash = sha256(item.response().toByteArray().getBytes());
                    if (!responseHash.equalsIgnoreCase(respHash)) continue;
                }
                setNegroContextNote(item.annotations(), contextLine);
                return true;
            }
            return false;
        } catch (Exception ex) {
            api.logging().logToError("Negro context sync exception: " + ex.getClass().getSimpleName() + ": " + (ex.getMessage() == null ? "" : ex.getMessage()));
            return false;
        }
    }

    private void applyStateAnnotation(HttpRequestResponse rr, String state) {
        try {
            Annotations a = rr.annotations();
            a.setHighlightColor(stateColor(state));
            appendNegroNote(a, "NEGRO · " + stateLabel(state));
        } catch (Exception ex) {
            api.logging().logToError("Negro annotations: " + ex.getMessage());
        }
    }

    private void setStateFromBurp(List<HttpRequestResponse> selected, String tool, String state) {
        if (selected == null || selected.isEmpty()) return;
        int changed = 0;
        for (HttpRequestResponse rr : selected) {
            if (rr == null || rr.request() == null || isNegroBridgeTraffic(rr.request().url())) continue;
            BridgeContext ctx = ingestContext(rr, tool);
            try {
                postBridgeAction(ctx, "set_state", kv("state", state));
                applyStateAnnotation(rr, state);
                changed++;
            } catch (Exception ex) { throw new IllegalStateException(ex); }
        }
        showMessage("Negro", changed + " item(s) → " + stateLabel(state), JOptionPane.INFORMATION_MESSAGE);
    }

    private List<IdentityChoice> identityChoices(String targetKey) {
        try {
            String json = getText("/api/bridge/identities/" + targetKey);
            List<IdentityChoice> out = new ArrayList<>();
            Pattern p = Pattern.compile("\\{\\\"identity_id\\\":(\\d+),\\\"context_id\\\":(null|\\d+),\\\"label\\\":\\\"((?:\\\\.|[^\\\"\\\\])*)\\\"\\}");
            Matcher m = p.matcher(json);
            while (m.find()) out.add(new IdentityChoice(Long.parseLong(m.group(1)), "null".equals(m.group(2)) ? 0 : Long.parseLong(m.group(2)), unescapeJson(m.group(3))));
            return out;
        } catch (Exception ex) { throw new IllegalStateException(ex); }
    }

    private IdentityChoice chooseIdentity(String targetKey, String title, boolean includeAnonymous) {
        List<IdentityChoice> list = identityChoices(targetKey);
        if (includeAnonymous) list.add(0, new IdentityChoice(0, 0, "Anonymous (remove known auth)"));
        if (list.isEmpty()) { showMessage("Negro", "Todavía no hay Identity Contexts. Usa Create Identity from this request.", JOptionPane.INFORMATION_MESSAGE); return null; }
        JComboBox<IdentityChoice> combo = new JComboBox<>(list.toArray(new IdentityChoice[0]));
        JPanel panel = formPanel(); panel.add(new JLabel("Identity Context")); panel.add(combo);
        return confirmDialog(title, panel) == JOptionPane.OK_OPTION ? (IdentityChoice) combo.getSelectedItem() : null;
    }

    private List<FlowChoice> flowChoices(String targetKey, boolean onlyCapturing) {
        try {
            String json = getText("/api/bridge/flows/" + targetKey);
            List<FlowChoice> out = new ArrayList<>();
            Pattern p = Pattern.compile("\\{\\\"id\\\":(\\d+),\\\"name\\\":\\\"((?:\\\\.|[^\\\"\\\\])*)\\\".*?\\\"capture_status\\\":\\\"((?:\\\\.|[^\\\"\\\\])*)\\\"", Pattern.DOTALL);
            Matcher m = p.matcher(json);
            while (m.find()) {
                FlowChoice f = new FlowChoice(Long.parseLong(m.group(1)), unescapeJson(m.group(2)), unescapeJson(m.group(3)));
                if (!onlyCapturing || "capturing".equals(f.captureStatus())) out.add(f);
            }
            return out;
        } catch (Exception ex) { throw new IllegalStateException(ex); }
    }

    private FlowChoice chooseFlow(String targetKey, String title, boolean onlyCapturing) {
        List<FlowChoice> list = flowChoices(targetKey, onlyCapturing);
        if (list.isEmpty()) { showMessage("Negro", onlyCapturing ? "No hay ningún Flow capturando en este target." : "Este target todavía no tiene Flows.", JOptionPane.INFORMATION_MESSAGE); return null; }
        JComboBox<FlowChoice> combo = new JComboBox<>(list.toArray(new FlowChoice[0]));
        JPanel panel = formPanel(); panel.add(new JLabel("Flow")); panel.add(combo);
        return confirmDialog(title, panel) == JOptionPane.OK_OPTION ? (FlowChoice) combo.getSelectedItem() : null;
    }

    private List<InvestigationChoice> investigationChoices(String targetKey) {
        try {
            String json = getText("/api/bridge/investigations/" + targetKey);
            List<InvestigationChoice> out = new ArrayList<>();
            Pattern p = Pattern.compile("\\{\\s*\\\"id\\\"\\s*:\\s*(\\d+).*?\\\"title\\\"\\s*:\\s*\\\"((?:\\\\.|[^\\\"\\\\])*)\\\".*?\\\"status\\\"\\s*:\\s*\\\"((?:\\\\.|[^\\\"\\\\])*)\\\"", Pattern.DOTALL);
            Matcher m = p.matcher(json);
            while (m.find()) out.add(new InvestigationChoice(Long.parseLong(m.group(1)), unescapeJson(m.group(2)), unescapeJson(m.group(3))));
            return out;
        } catch (Exception ex) { throw new IllegalStateException(ex); }
    }

    private InvestigationChoice chooseInvestigation(String targetKey, String title, boolean allowNone) {
        List<InvestigationChoice> list = investigationChoices(targetKey);
        if (allowNone) list.add(0, new InvestigationChoice(0, "Sin Investigation", ""));
        if (list.isEmpty()) { showMessage("Negro", "Todavía no hay Investigations activas.", JOptionPane.INFORMATION_MESSAGE); return null; }
        JComboBox<InvestigationChoice> combo = new JComboBox<>(list.toArray(new InvestigationChoice[0]));
        JPanel panel = formPanel(); panel.add(new JLabel("Investigation")); panel.add(combo);
        return confirmDialog(title, panel) == JOptionPane.OK_OPTION ? (InvestigationChoice) combo.getSelectedItem() : null;
    }

    private List<HypothesisChoice> hypothesisChoices(String targetKey) {
        try {
            String json = getText("/api/bridge/hypotheses/" + targetKey);
            List<HypothesisChoice> out = new ArrayList<>();
            Pattern p = Pattern.compile("\\{\\s*\\\"id\\\"\\s*:\\s*(\\d+).*?\\\"title\\\"\\s*:\\s*\\\"((?:\\\\.|[^\\\"\\\\])*)\\\".*?\\\"status\\\"\\s*:\\s*\\\"((?:\\\\.|[^\\\"\\\\])*)\\\"", Pattern.DOTALL);
            Matcher m = p.matcher(json);
            while (m.find()) out.add(new HypothesisChoice(Long.parseLong(m.group(1)), unescapeJson(m.group(2)), unescapeJson(m.group(3))));
            return out;
        } catch (Exception ex) { throw new IllegalStateException(ex); }
    }

    private HypothesisChoice chooseHypothesis(String targetKey, String title) {
        List<HypothesisChoice> list = hypothesisChoices(targetKey);
        if (list.isEmpty()) { showMessage("Negro", "Todavía no hay Hypotheses en este target.", JOptionPane.INFORMATION_MESSAGE); return null; }
        JComboBox<HypothesisChoice> combo = new JComboBox<>(list.toArray(new HypothesisChoice[0]));
        JPanel panel = formPanel(); panel.add(new JLabel("Hypothesis")); panel.add(combo);
        return confirmDialog(title, panel) == JOptionPane.OK_OPTION ? (HypothesisChoice) combo.getSelectedItem() : null;
    }

    private List<ParameterChoice> parameterChoices(String targetKey, long exchangeId) {
        try {
            String json = getText("/api/bridge/exchange-context/" + targetKey + "/" + exchangeId);
            List<ParameterChoice> out = new ArrayList<>();
            Pattern p = Pattern.compile("\\{\\s*\\\"id\\\"\\s*:\\s*(\\d+),\\s*\\\"name\\\"\\s*:\\s*\\\"((?:\\\\.|[^\\\"\\\\])*)\\\",\\s*\\\"normalized_name\\\"\\s*:\\s*\\\"((?:\\\\.|[^\\\"\\\\])*)\\\",\\s*\\\"value_preview\\\"\\s*:\\s*(?:null|\\\"((?:\\\\.|[^\\\"\\\\])*)\\\"),\\s*\\\"value_raw\\\"\\s*:\\s*(?:null|\\\"((?:\\\\.|[^\\\"\\\\])*)\\\"),\\s*\\\"location\\\"\\s*:\\s*(?:null|\\\"((?:\\\\.|[^\\\"\\\\])*)\\\")", Pattern.DOTALL);
            Matcher m = p.matcher(json);
            while (m.find()) {
                String raw = m.group(5) != null ? unescapeJson(m.group(5)) : (m.group(4) == null ? "" : unescapeJson(m.group(4)));
                out.add(new ParameterChoice(Long.parseLong(m.group(1)), unescapeJson(m.group(2)), unescapeJson(m.group(3)), raw, m.group(6) == null ? "" : unescapeJson(m.group(6))));
            }
            return out;
        } catch (Exception ex) { throw new IllegalStateException(ex); }
    }

    private int bestParameterIndex(List<ParameterChoice> list, String selected) {
        if (selected == null || selected.isBlank()) return 0;
        String clean = selected.trim();
        for (int i = 0; i < list.size(); i++) if (clean.equals(list.get(i).value())) return i;
        for (int i = 0; i < list.size(); i++) if (clean.equalsIgnoreCase(list.get(i).normalizedName()) || clean.equalsIgnoreCase(list.get(i).name())) return i;
        return 0;
    }

    private void attachInvestigationFromBurp(HttpRequestResponse rr, String tool) {
        BridgeContext ctx = ingestContext(rr, tool);
        InvestigationChoice inv = chooseInvestigation(ctx.targetKey(), "Añadir a Investigation", false); if (inv == null) return;
        try {
            postBridgeAction(ctx, "investigation_attach", "\"investigation_id\":" + inv.id());
            appendNegroNote(rr.annotations(), "NEGRO · INV · " + inv.title());
            showMessage("Negro", "Request #" + ctx.exchangeId() + " añadida a " + inv.title(), JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ex) { throw new IllegalStateException(ex); }
    }

    private void createInvestigationFromBurp(HttpRequestResponse rr, String tool) {
        BridgeContext ctx = ingestContext(rr, tool);
        JTextField title = new JTextField("Investigación desde " + rr.request().method(), 36);
        JTextArea summary = new JTextArea(4, 36); summary.setLineWrap(true); summary.setWrapStyleWord(true);
        JPanel panel = formPanel(); panel.add(new JLabel("Nombre")); panel.add(title); panel.add(new JLabel("Resumen")); panel.add(new JScrollPane(summary));
        if (confirmDialog("Crear Investigation", panel) != JOptionPane.OK_OPTION) return;
        if (title.getText().trim().isEmpty()) return;
        try {
            String body = postBridgeAction(ctx, "investigation_create", kv("title", title.getText().trim()) + "," + kv("summary", summary.getText().trim()));
            long iid = jsonLong(body, "investigation_id");
            String invTitle = jsonString(body, "title");
            appendNegroNote(rr.annotations(), "NEGRO · INV · " + (invTitle == null ? ("#" + iid) : invTitle));
            showMessage("Negro", "Investigation #" + iid + " creada con esta Request como evidencia.", JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ex) { throw new IllegalStateException(ex); }
    }

    private void createHypothesisFromBurp(HttpRequestResponse rr, String tool) {
        BridgeContext ctx = ingestContext(rr, tool);
        JTextField question = new JTextField(40);
        JTextArea why = new JTextArea(3, 40); why.setLineWrap(true); why.setWrapStyleWord(true);
        JTextArea next = new JTextArea(3, 40); next.setLineWrap(true); next.setWrapStyleWord(true);
        List<InvestigationChoice> invs = investigationChoices(ctx.targetKey()); invs.add(0, new InvestigationChoice(0, "Sin Investigation", ""));
        JComboBox<InvestigationChoice> invCombo = new JComboBox<>(invs.toArray(new InvestigationChoice[0]));
        JPanel panel = formPanel(); panel.add(new JLabel("Pregunta")); panel.add(question); panel.add(new JLabel("Por qué tiene sentido")); panel.add(new JScrollPane(why)); panel.add(new JLabel("Qué probar")); panel.add(new JScrollPane(next)); panel.add(new JLabel("Investigation opcional")); panel.add(invCombo);
        if (confirmDialog("Crear Hypothesis", panel) != JOptionPane.OK_OPTION) return;
        if (question.getText().trim().isEmpty()) return;
        InvestigationChoice inv = (InvestigationChoice) invCombo.getSelectedItem();
        try {
            String extra = kv("title", question.getText().trim()) + "," + kv("why", why.getText().trim()) + "," + kv("next_test", next.getText().trim()) + ",\"investigation_id\":" + (inv == null ? 0 : inv.id());
            String body = postBridgeAction(ctx, "hypothesis_create", extra);
            long hid = jsonLong(body, "hypothesis_id");
            appendNegroNote(rr.annotations(), "NEGRO · HYP · #" + hid + " · " + question.getText().trim());
            showMessage("Negro", "Hypothesis #" + hid + " creada con esta Request como evidencia.", JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ex) { throw new IllegalStateException(ex); }
    }

    private void attachHypothesisFromBurp(HttpRequestResponse rr, String tool) {
        BridgeContext ctx = ingestContext(rr, tool);
        HypothesisChoice hyp = chooseHypothesis(ctx.targetKey(), "Adjuntar a Hypothesis"); if (hyp == null) return;
        try {
            postBridgeAction(ctx, "hypothesis_attach", "\"hypothesis_id\":" + hyp.id());
            appendNegroNote(rr.annotations(), "NEGRO · HYP · #" + hyp.id() + " · " + hyp.title());
            showMessage("Negro", "Request #" + ctx.exchangeId() + " añadida como evidencia a Hypothesis #" + hyp.id(), JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ex) { throw new IllegalStateException(ex); }
    }

    private void createEntityFromBurp(HttpRequestResponse rr, String tool, String selectedText) {
        BridgeContext ctx = ingestContext(rr, tool);
        List<ParameterChoice> params = parameterChoices(ctx.targetKey(), ctx.exchangeId());
        if (params.isEmpty()) { showMessage("Negro", "Esta Request no tiene keys/values estructurados para convertir en Entity.", JOptionPane.INFORMATION_MESSAGE); return; }
        JComboBox<ParameterChoice> paramCombo = new JComboBox<>(params.toArray(new ParameterChoice[0]));
        paramCombo.setSelectedIndex(Math.min(bestParameterIndex(params, selectedText), params.size() - 1));
        ParameterChoice suggested = (ParameterChoice) paramCombo.getSelectedItem();
        String key = suggested == null ? "Object" : suggested.normalizedName().toLowerCase();
        String guess = key.contains("order") ? "Order" : key.contains("return") ? "Return" : key.contains("refund") ? "Refund" : key.contains("payment") ? "Payment" : key.contains("user") || key.contains("customer") || key.contains("account") ? "User" : "Object";
        JTextField type = new JTextField(guess, 24);
        List<InvestigationChoice> invs = investigationChoices(ctx.targetKey()); invs.add(0, new InvestigationChoice(0, "Sin Investigation", ""));
        JComboBox<InvestigationChoice> invCombo = new JComboBox<>(invs.toArray(new InvestigationChoice[0]));
        JPanel panel = formPanel(); panel.add(new JLabel("Key / valor observado")); panel.add(paramCombo); panel.add(new JLabel("Tipo de Entity")); panel.add(type); panel.add(new JLabel("Investigation opcional")); panel.add(invCombo);
        if (confirmDialog("Crear Entity", panel) != JOptionPane.OK_OPTION) return;
        ParameterChoice choice = (ParameterChoice) paramCombo.getSelectedItem(); if (choice == null || type.getText().trim().isEmpty()) return;
        InvestigationChoice inv = (InvestigationChoice) invCombo.getSelectedItem();
        try {
            String body = postBridgeAction(ctx, "entity_create", "\"observation_id\":" + choice.id() + "," + kv("entity_type", type.getText().trim()) + ",\"investigation_id\":" + (inv == null ? 0 : inv.id()));
            long boid = jsonLong(body, "business_object_id");
            appendNegroNote(rr.annotations(), "NEGRO · ENTITY · " + type.getText().trim() + " " + choice.value());
            showMessage("Negro", "Entity " + type.getText().trim() + " creada/actualizada" + (boid > 0 ? " (#" + boid + ")" : "") + ".", JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ex) { throw new IllegalStateException(ex); }
    }

    private void followValueFromBurp(HttpRequestResponse rr, String tool, String selectedText) {
        BridgeContext ctx = ingestContext(rr, tool);
        List<ParameterChoice> params = parameterChoices(ctx.targetKey(), ctx.exchangeId());
        JComboBox<String> mode = new JComboBox<>(new String[]{"Valor exacto", "Key / parámetro"});
        JComboBox<ParameterChoice> paramCombo = new JComboBox<>(params.toArray(new ParameterChoice[0]));
        if (!params.isEmpty()) paramCombo.setSelectedIndex(Math.min(bestParameterIndex(params, selectedText), params.size() - 1));
        JTextField selected = new JTextField(selectedText == null ? "" : selectedText, 34);
        JPanel panel = formPanel(); panel.add(new JLabel("Selección de Burp (opcional)")); panel.add(selected); panel.add(new JLabel("O usa una pieza estructurada de esta Request")); panel.add(paramCombo); panel.add(new JLabel("Seguir como")); panel.add(mode);
        if (confirmDialog("Seguir key / valor", panel) != JOptionPane.OK_OPTION) return;
        ParameterChoice pc = (ParameterChoice) paramCombo.getSelectedItem();
        boolean keyMode = mode.getSelectedIndex() == 1;
        String raw = selected.getText().trim();
        if (raw.isEmpty() && pc != null) raw = keyMode ? pc.normalizedName() : pc.value();
        if (raw.isEmpty()) return;
        try {
            String body = postBridgeAction(ctx, "follow_value", kv("mode", keyMode ? "key" : "value") + "," + kv("selected", raw) + ",\"observation_id\":" + (pc == null ? 0 : pc.id()));
            String web = jsonString(body, "web_path");
            if (web != null) openBrowser(negroBaseUrl + web);
        } catch (Exception ex) { throw new IllegalStateException(ex); }
    }

    private void createWatchFromBurp(HttpRequestResponse rr, String tool, String selectedText) {
        BridgeContext ctx = ingestContext(rr, tool);
        List<WatchTargetChoice> targets = new ArrayList<>();
        for (HypothesisChoice h : hypothesisChoices(ctx.targetKey())) targets.add(new WatchTargetChoice("hypothesis", h.id(), h.title()));
        for (InvestigationChoice i : investigationChoices(ctx.targetKey())) targets.add(new WatchTargetChoice("investigation", i.id(), i.title()));
        if (targets.isEmpty()) { showMessage("Negro", "Crea primero una Hypothesis o Investigation para alojar el Watch.", JOptionPane.INFORMATION_MESSAGE); return; }
        JComboBox<WatchTargetChoice> targetCombo = new JComboBox<>(targets.toArray(new WatchTargetChoice[0]));
        JComboBox<String> typeCombo = new JComboBox<>(new String[]{"key", "value", "endpoint", "entity_type", "regex"});
        JTextField pattern = new JTextField(selectedText == null ? "" : selectedText, 34);
        JTextArea description = new JTextArea(3, 34); description.setLineWrap(true); description.setWrapStyleWord(true);
        JCheckBox dependency = new JCheckBox("Si es Hypothesis, marcar como dependencia bloqueante", true);
        JPanel panel = formPanel(); panel.add(new JLabel("Vincular a")); panel.add(targetCombo); panel.add(new JLabel("Tipo de Watch")); panel.add(typeCombo); panel.add(new JLabel("Patrón")); panel.add(pattern); panel.add(new JLabel("Qué estás esperando")); panel.add(new JScrollPane(description)); panel.add(dependency);
        if (confirmDialog("Crear Watch", panel) != JOptionPane.OK_OPTION) return;
        WatchTargetChoice target = (WatchTargetChoice) targetCombo.getSelectedItem(); if (target == null || pattern.getText().trim().isEmpty()) return;
        try {
            String extra = kv("watch_type", String.valueOf(typeCombo.getSelectedItem())) + "," + kv("pattern", pattern.getText().trim()) + "," + kv("description", description.getText().trim()) + ",\"hypothesis_id\":" + ("hypothesis".equals(target.kind()) ? target.id() : 0) + ",\"investigation_id\":" + ("investigation".equals(target.kind()) ? target.id() : 0) + ",\"as_requirement\":" + (dependency.isSelected() && "hypothesis".equals(target.kind()) ? "true" : "false");
            String body = postBridgeAction(ctx, "watch_create", extra);
            long wid = jsonLong(body, "watch_id");
            appendNegroNote(rr.annotations(), "NEGRO · WATCH · " + typeCombo.getSelectedItem() + "=" + pattern.getText().trim());
            showMessage("Negro", "Watch #" + wid + " creado para " + target.label(), JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ex) { throw new IllegalStateException(ex); }
    }

    private List<AuthMaterialChoice> authMaterialChoices(String targetKey, long exchangeId) {
        try {
            String json = getText("/api/bridge/auth-materials/" + targetKey + "/" + exchangeId);
            List<AuthMaterialChoice> out = new ArrayList<>();
            Pattern p = Pattern.compile("\\{\\\"fingerprint\\\":\\\"([^\\\"]+)\\\",\\\"material_type\\\":\\\"([^\\\"]+)\\\",\\\"name\\\":\\\"((?:\\\\.|[^\\\"\\\\])*)\\\",\\\"preview\\\":\\\"((?:\\\\.|[^\\\"\\\\])*)\\\"\\}");
            Matcher m = p.matcher(json);
            while (m.find()) out.add(new AuthMaterialChoice(m.group(1), m.group(2), unescapeJson(m.group(3)), unescapeJson(m.group(4))));
            return out;
        } catch (Exception ex) { throw new IllegalStateException(ex); }
    }

    private List<String> chooseAuthFingerprints(String targetKey, long exchangeId, String title) {
        List<AuthMaterialChoice> materials = authMaterialChoices(targetKey, exchangeId);
        if (materials.isEmpty()) { showMessage("Negro", "No detecté Authorization, cookies ni headers de auth conocidos en esta request.", JOptionPane.INFORMATION_MESSAGE); return null; }
        JPanel panel = formPanel(); panel.add(new JLabel("Selecciona el material que pertenece a esta identidad:"));
        List<JCheckBox> boxes = new ArrayList<>();
        for (AuthMaterialChoice material : materials) {
            JCheckBox box = new JCheckBox(material.toString(), true);
            boxes.add(box); panel.add(box);
        }
        if (confirmDialog(title, panel) != JOptionPane.OK_OPTION) return null;
        List<String> out = new ArrayList<>();
        for (int i = 0; i < boxes.size(); i++) if (boxes.get(i).isSelected()) out.add(materials.get(i).fingerprint());
        return out;
    }

    private void assignIdentityFromBurp(HttpRequestResponse rr, String tool) {
        BridgeContext ctx = ingestContext(rr, tool);
        IdentityChoice choice = chooseIdentity(ctx.targetKey(), "Assign to Identity", false); if (choice == null) return;
        try {
            postBridgeAction(ctx, "identity_assign", "\"identity_id\":" + choice.identityId() + ",\"context_id\":" + (choice.contextId() > 0 ? Long.toString(choice.contextId()) : "null") + ",\"learn_auth\":false");
            appendNegroNote(rr.annotations(), "NEGRO · IDENTITY · " + choice.label());
            showMessage("Negro", "Exchange #" + ctx.exchangeId() + " → " + choice.label(), JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ex) { throw new IllegalStateException(ex); }
    }

    private void createIdentityFromBurp(HttpRequestResponse rr, String tool) {
        BridgeContext ctx = ingestContext(rr, tool);
        List<String> fingerprints = chooseAuthFingerprints(ctx.targetKey(), ctx.exchangeId(), "Create Identity · auth material");
        if (fingerprints == null) return;
        JTextField name = new JTextField(32);
        JPanel panel = formPanel(); panel.add(new JLabel("Nombre de la identidad")); panel.add(name);
        if (confirmDialog("Create Identity from this request", panel) != JOptionPane.OK_OPTION) return;
        String identityName = name.getText().trim(); if (identityName.isEmpty()) return;
        try {
            String extra = kv("name", identityName) + "," + kv("material_fingerprints", String.join(",", fingerprints));
            String body = postBridgeAction(ctx, "identity_create", extra);
            long id = jsonLong(body, "identity_id");
            appendNegroNote(rr.annotations(), "NEGRO · IDENTITY · " + identityName);
            showMessage("Negro", "Identity #" + id + " creada y asociada al exchange #" + ctx.exchangeId(), JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ex) { throw new IllegalStateException(ex); }
    }

    private void updateIdentityAuthFromBurp(HttpRequestResponse rr, String tool) {
        BridgeContext ctx = ingestContext(rr, tool);
        IdentityChoice choice = chooseIdentity(ctx.targetKey(), "Update auth material", false); if (choice == null) return;
        List<String> fingerprints = chooseAuthFingerprints(ctx.targetKey(), ctx.exchangeId(), "Auth actual de " + choice.label());
        if (fingerprints == null || fingerprints.isEmpty()) return;
        try {
            String extra = "\"identity_id\":" + choice.identityId() + ",\"context_id\":" + (choice.contextId() > 0 ? Long.toString(choice.contextId()) : "null") + "," + kv("material_fingerprints", String.join(",", fingerprints));
            postBridgeAction(ctx, "identity_update_auth", extra);
            appendNegroNote(rr.annotations(), "NEGRO · AUTH UPDATED · " + choice.label());
            showMessage("Negro", "Auth actualizada para " + choice.label(), JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ex) { throw new IllegalStateException(ex); }
    }

    private void sendAsIdentityFromBurp(HttpRequestResponse rr, String tool) {
        BridgeContext ctx = ingestContext(rr, tool);
        IdentityChoice choice = chooseIdentity(ctx.targetKey(), "Send / Re-send as Identity", true); if (choice == null) return;
        try {
            String extra = "\"identity_id\":" + choice.identityId() + ",\"context_id\":" + (choice.contextId() > 0 ? Long.toString(choice.contextId()) : "null");
            postBridgeAction(ctx, "identity_send_as", extra);
            showMessage("Negro", "Enviado a Repeater como " + choice.label() + ". Método/path/body se conservan; sólo cambia auth conocida.", JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ex) { throw new IllegalStateException(ex); }
    }

    private void prepareReplayFromContext(HttpRequestResponse rr, BridgeContext ctx, IdentityChoice choice) {
        try {
            String extra = "\"identity_id\":" + choice.identityId() + ",\"context_id\":" + (choice.contextId() > 0 ? Long.toString(choice.contextId()) : "null");
            String body = postBridgeAction(ctx, "replay_prepare", extra);
            String web = jsonString(body, "web_path");
            appendNegroNote(rr.annotations(), "NEGRO · REPLAY PREPARED · " + choice.label());
            if (web == null || web.isBlank()) throw new IllegalStateException("Negro no devolvió la vista del Replay");
            openBrowser(negroBaseUrl + web);
        } catch (Exception ex) { throw new IllegalStateException(ex); }
    }

    private void prepareReplayFromBurp(HttpRequestResponse rr, String tool, IdentityChoice choice) {
        prepareReplayFromContext(rr, ingestContext(rr, tool), choice);
    }

    private void openReplayChooserFromContext(BridgeContext ctx) {
        openBrowser(negroBaseUrl + "/t/" + ctx.targetKey() + "/replays/new?exchange_id=" + ctx.exchangeId());
    }

    private void openReplayChooserFromBurp(HttpRequestResponse rr, String tool) {
        openReplayChooserFromContext(ingestContext(rr, tool));
    }

    private void startFlowFromBurp(HttpRequestResponse rr, String tool) {
        BridgeContext ctx = ingestContext(rr, tool);
        JTextField name = new JTextField("Flow from " + rr.request().method(), 32);
        JTextArea description = new JTextArea(3, 32); description.setLineWrap(true); description.setWrapStyleWord(true);
        JPanel panel = formPanel(); panel.add(new JLabel("Nombre")); panel.add(name); panel.add(new JLabel("Descripción opcional")); panel.add(new JScrollPane(description));
        if (confirmDialog("Start Flow from here", panel) != JOptionPane.OK_OPTION) return;
        if (name.getText().trim().isEmpty()) return;
        try {
            String body = postBridgeAction(ctx, "flow_start", kv("name", name.getText().trim()) + "," + kv("description", description.getText().trim()));
            long flowId = jsonLong(body, "flow_id");
            appendNegroNote(rr.annotations(), "NEGRO · FLOW START · #" + flowId);
            showMessage("Negro", "Flow #" + flowId + " capturando desde exchange #" + ctx.exchangeId(), JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ex) { throw new IllegalStateException(ex); }
    }

    private void endFlowFromBurp(HttpRequestResponse rr, String tool) {
        BridgeContext ctx = ingestContext(rr, tool);
        FlowChoice flow = chooseFlow(ctx.targetKey(), "End Flow here", true); if (flow == null) return;
        try {
            postBridgeAction(ctx, "flow_end", "\"flow_id\":" + flow.id());
            appendNegroNote(rr.annotations(), "NEGRO · FLOW END · #" + flow.id());
            showMessage("Negro", "Flow #" + flow.id() + " detenido en exchange #" + ctx.exchangeId() + ". Revisa candidatos/ruido en Negro.", JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ex) { throw new IllegalStateException(ex); }
    }

    private void addToFlowFromBurp(HttpRequestResponse rr, String tool) {
        BridgeContext ctx = ingestContext(rr, tool);
        FlowChoice flow = chooseFlow(ctx.targetKey(), "Add to Flow", false); if (flow == null) return;
        try {
            postBridgeAction(ctx, "flow_add", "\"flow_id\":" + flow.id());
            appendNegroNote(rr.annotations(), "NEGRO · FLOW #" + flow.id());
            showMessage("Negro", "Exchange #" + ctx.exchangeId() + " agregado a Flow #" + flow.id(), JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ex) { throw new IllegalStateException(ex); }
    }

    private void createFlowFromSelection(List<HttpRequestResponse> selected, String tool) {
        if (selected == null || selected.isEmpty()) return;
        List<BridgeContext> contexts = new ArrayList<>();
        for (HttpRequestResponse rr : selected) contexts.add(ingestContext(rr, tool));
        String targetKey = contexts.get(0).targetKey();
        if (contexts.stream().anyMatch(c -> !targetKey.equals(c.targetKey()))) throw new IllegalStateException("La selección contiene exchanges de targets distintos");
        JTextField name = new JTextField("Flow from Burp selection", 34);
        JPanel panel = formPanel(); panel.add(new JLabel("Nombre para " + contexts.size() + " exchange(s) seleccionados")); panel.add(name);
        if (confirmDialog("Create Flow from selected exchanges", panel) != JOptionPane.OK_OPTION) return;
        if (name.getText().trim().isEmpty()) return;
        String ids = contexts.stream().map(c -> Long.toString(c.exchangeId())).collect(Collectors.joining(","));
        try {
            String body = postBridgeAction(contexts.get(0), "flow_create_selected", kv("name", name.getText().trim()) + "," + kv("exchange_ids", ids));
            long flowId = jsonLong(body, "flow_id");
            for (HttpRequestResponse rr : selected) appendNegroNote(rr.annotations(), "NEGRO · FLOW #" + flowId);
            showMessage("Negro", "Flow #" + flowId + " creado con " + contexts.size() + " exchange(s) exactos.", JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ex) { throw new IllegalStateException(ex); }
    }

    private void addNoteFromBurp(List<HttpRequestResponse> selected, String tool) {
        if (selected == null || selected.isEmpty()) return;
        BridgeContext first = ingestContext(selected.get(0), tool);
        List<InvestigationChoice> invs = investigationChoices(first.targetKey());
        invs.add(0, new InvestigationChoice(0, "Sólo en la Request", ""));
        JComboBox<InvestigationChoice> invCombo = new JComboBox<>(invs.toArray(new InvestigationChoice[0]));
        JTextArea notes = new JTextArea(5, 38); notes.setLineWrap(true); notes.setWrapStyleWord(true);
        JPanel form = formPanel(); form.add(new JLabel("Nota para " + selected.size() + " item(s)")); form.add(new JScrollPane(notes)); form.add(new JLabel("También guardar en Investigation")); form.add(invCombo);
        if (confirmDialog("Negro · Agregar nota", form) != JOptionPane.OK_OPTION) return;
        String note = notes.getText().trim();
        if (note.isEmpty()) return;
        InvestigationChoice inv = (InvestigationChoice) invCombo.getSelectedItem();
        for (int idx = 0; idx < selected.size(); idx++) {
            HttpRequestResponse rr = selected.get(idx);
            BridgeContext ctx = idx == 0 ? first : ingestContext(rr, tool);
            try {
                postBridgeAction(ctx, "add_note", kv("note", note) + ",\"investigation_id\":" + (inv == null ? 0 : inv.id()));
                appendNegroNote(rr.annotations(), "NEGRO · NOTE · " + note.replace('\n', ' '));
                if (inv != null && inv.id() > 0) appendNegroNote(rr.annotations(), "NEGRO · INV · " + inv.title());
            } catch (Exception ex) { throw new IllegalStateException(ex); }
        }
        showMessage("Negro", "Nota guardada en " + selected.size() + " item(s)." + (inv != null && inv.id() > 0 ? " · " + inv.title() : ""), JOptionPane.INFORMATION_MESSAGE);
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
            appendNegroNote(rr.annotations(), "NEGRO · FIND · #" + fid);
            showMessage("Negro", "Finding #" + fid + " creado con esta request/response como evidencia.", JOptionPane.INFORMATION_MESSAGE);
            if (web != null && askYesNo("Negro", "¿Abrir el Finding en Negro?")) openBrowser(negroBaseUrl + web);
        } catch (Exception ex) { throw new IllegalStateException(ex); }
    }

    private void attachFindingFromBurp(HttpRequestResponse rr, String tool) {
        BridgeContext ctx = ingestContext(rr, tool);
        FindingChoice finding = chooseFinding(ctx.targetKey(), "Attach to existing Finding"); if (finding == null) return;
        try {
            postBridgeAction(ctx, "attach_finding", "\"finding_id\":" + finding.id());
            appendNegroNote(rr.annotations(), "NEGRO · FIND · #" + finding.id());
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
            appendNegroNote(rr.annotations(), "NEGRO · RETEST · FIND #" + finding.id());
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
