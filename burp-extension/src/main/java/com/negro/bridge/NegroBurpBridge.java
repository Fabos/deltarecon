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
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import burp.api.montoya.ui.editor.extension.HttpRequestEditorProvider;
import burp.api.montoya.ui.editor.extension.HttpResponseEditorProvider;

import javax.swing.*;
import javax.swing.event.MenuEvent;
import javax.swing.event.MenuListener;
import javax.swing.text.AttributeSet;
import javax.swing.text.DefaultHighlighter;
import javax.swing.text.Highlighter;
import javax.swing.text.BadLocationException;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;
import java.awt.*;
import java.awt.geom.Rectangle2D;
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
 * Negro Burp Bridge v0.39.0
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
    private final AtomicLong lastScopeReconcileMs = new AtomicLong(0L);
    private volatile String negroBaseUrl = System.getProperty("negro.url", "http://127.0.0.1:8765");
    private JLabel statusLabel;
    private JLabel lastErrorLabel;
    private Timer uiTimer;
    private volatile String lastErrorDetail = "";
    private volatile long lastSuccessfulContactMs = 0L;
    private final String bridgeInstanceId = UUID.randomUUID().toString();
    private final AtomicBoolean unloading = new AtomicBoolean(false);
    private final Set<String> runnerBridgeInFlight = ConcurrentHashMap.newKeySet();
    private final Set<String> scopeHostsAlreadyPrompted = ConcurrentHashMap.newKeySet();
    private final ScheduledExecutorService bridgePoller = Executors.newSingleThreadScheduledExecutor(r -> { Thread t = new Thread(r, "negro-repeater-bridge"); t.setDaemon(true); return t; });

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("Negro Burp Bridge");
        api.logging().logToOutput("Negro Burp Bridge v0.39.0 iniciado → " + negroBaseUrl + " · instance=" + bridgeInstanceId.substring(0, 8));
        api.extension().registerUnloadingHandler(() -> {
            if (unloading.compareAndSet(false, true)) {
                bridgePoller.shutdownNow();
                if (uiTimer != null) SwingUtilities.invokeLater(() -> uiTimer.stop());
                api.logging().logToOutput("Negro Burp Bridge descargado · poller detenido · instance=" + bridgeInstanceId.substring(0, 8));
            }
        });
        api.http().registerHttpHandler(new BridgeHttpHandler());
        api.scope().registerScopeChangeHandler(change -> {
            // Scope events do not carry the changed URL. Reconcile only the small set
            // of configured project roots and inspect Site map for a new unassigned host.
            bridgePoller.schedule(() -> reconcileBurpScope("scope-change"), 250, TimeUnit.MILLISECONDS);
            bridgePoller.schedule(this::promptUnassignedInScopeHosts, 500, TimeUnit.MILLISECONDS);
        });
        api.userInterface().registerContextMenuItemsProvider(new NegroContextMenu());
        api.userInterface().registerHttpRequestEditorProvider(new NegroContextRequestProvider());
        api.userInterface().registerHttpResponseEditorProvider(new NegroContextResponseProvider());
        api.userInterface().registerSuiteTab("Negro", buildPanel());
        healthCheck();
        bridgePoller.schedule(() -> reconcileBurpScope("startup"), 700, TimeUnit.MILLISECONDS);
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
                    if (r.statusCode() == 200) {
                        markConnected("health OK");
                    }
                    else SwingUtilities.invokeLater(() -> { if (statusLabel != null) statusLabel.setText("○ Negro respondió HTTP " + r.statusCode()); });
                })
                .exceptionally(ex -> {
                    markUnavailable(ex);
                    return null;
                });
    }

    private record ContextMark(int start, int end, String kind, String label, String reason, String sourceExchangeId) {}
    private record RenderedHttp(String text, List<ContextMark> marks) {}

    private Color uiColor(String key, Color fallback) {
        Color c = UIManager.getColor(key);
        return c == null ? fallback : c;
    }

    private String decodeB64(String value) {
        if (value == null || value.isBlank()) return "";
        try { return new String(Base64.getDecoder().decode(value), StandardCharsets.UTF_8); }
        catch (Exception ex) { return ""; }
    }

    private String decodeUrlB64(String value) {
        if (value == null || value.isBlank()) return "";
        try { return new String(Base64.getUrlDecoder().decode(value), StandardCharsets.UTF_8); }
        catch (Exception ex) { return ""; }
    }

    private List<ContextMark> decodeContextMarks(String encoded) {
        List<ContextMark> out = new ArrayList<>();
        String raw = decodeB64(encoded);
        if (raw.isBlank()) return out;
        for (String line : raw.split("\\n")) {
            if (line == null || line.isBlank()) continue;
            String[] parts = line.split("\\|", -1);
            if (parts.length < 6) continue;
            try {
                int start = Integer.parseInt(parts[0]);
                int end = Integer.parseInt(parts[1]);
                if (start < 0 || end <= start) continue;
                out.add(new ContextMark(start, end, parts[2], decodeUrlB64(parts[3]), decodeUrlB64(parts[4]), parts[5]));
            } catch (Exception ignored) {}
        }
        return out;
    }

    private final class NegroContextView extends JPanel {
        private final JPanel header = new JPanel();
        private final JPanel metaRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        private final JLabel endpoint = new JLabel(" ");
        private final JButton openButton = new JButton("Open in Negro");
        private final JTextPane http = new JTextPane() {
            @Override public boolean getScrollableTracksViewportWidth() { return true; }
        };
        private final JScrollPane scroll;
        private String inspectorUrl = "";
        private final JPanel navRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 1));
        private final JLabel navStatus = new JLabel("0 elementos");
        private final JButton navPrev = new JButton("‹");
        private final JButton navNext = new JButton("›");
        private final List<Integer> navAnchors = new ArrayList<>();
        private String navFilter = "ALL";
        private int navIndex = -1;
        private Object navHighlightTag;
        private String sourceHttpText = "";
        private List<ContextMark> sourceHttpMarks = List.of();
        private boolean prettyMode = true;
        private final JToggleButton prettyToggle = new JToggleButton("Pretty", true);
        private final JToggleButton rawToggle = new JToggleButton("Raw", false);
        private static final Set<String> SECURITY_HEADERS = Set.of(
                "authorization", "proxy-authorization", "cookie", "set-cookie", "origin", "referer", "host",
                "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto", "x-original-url", "x-rewrite-url",
                "x-http-method-override", "x-method-override", "content-type", "location", "www-authenticate",
                "access-control-allow-origin", "access-control-allow-credentials", "access-control-request-method",
                "access-control-request-headers", "x-api-key", "api-key", "x-auth-token", "x-csrf-token", "x-xsrf-token"
        );

        NegroContextView() {
            super(new BorderLayout());
            setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 0));

            header.setLayout(new BoxLayout(header, BoxLayout.Y_AXIS));
            header.setBorder(BorderFactory.createEmptyBorder(9, 11, 8, 11));

            JPanel titleRow = new JPanel(new BorderLayout(8, 0));
            JLabel title = new JLabel("Negro Context");
            title.setFont(title.getFont().deriveFont(Font.BOLD, 14f));
            titleRow.add(title, BorderLayout.WEST);
            openButton.setFocusable(false);
            openButton.setMargin(new Insets(3, 10, 3, 10));
            openButton.setEnabled(false);
            openButton.addActionListener(e -> {
                if (inspectorUrl == null || inspectorUrl.isBlank()) return;
                try { Desktop.getDesktop().browse(URI.create(inspectorUrl)); }
                catch (Exception ex) { api.logging().logToError("Negro Context no pudo abrir Inspector: " + ex.getMessage()); }
            });
            titleRow.add(openButton, BorderLayout.EAST);
            header.add(titleRow);
            header.add(Box.createVerticalStrut(4));
            endpoint.setFont(endpoint.getFont().deriveFont(Font.PLAIN, 11f));
            endpoint.setForeground(uiColor("Label.disabledForeground", new Color(100, 108, 116)));
            header.add(endpoint);
            header.add(Box.createVerticalStrut(5));
            metaRow.setOpaque(false);
            header.add(metaRow);
            header.add(Box.createVerticalStrut(5));

            navRow.setOpaque(false);
            ButtonGroup navGroup = new ButtonGroup();
            ButtonGroup viewGroup = new ButtonGroup();
            viewGroup.add(prettyToggle);
            viewGroup.add(rawToggle);
            configureViewToggle(prettyToggle);
            configureViewToggle(rawToggle);
            prettyToggle.setToolTipText("Formatea bodies JSON sin modificar la evidencia original");
            rawToggle.setToolTipText("Muestra los bytes HTTP tal como Negro los almacenó");
            prettyToggle.addActionListener(e -> { prettyMode = true; renderSourceHttp(); });
            rawToggle.addActionListener(e -> { prettyMode = false; renderSourceHttp(); });
            navRow.add(prettyToggle);
            navRow.add(rawToggle);
            navRow.add(Box.createHorizontalStrut(5));
            navRow.add(navToggle("Todo", "ALL", true, navGroup));
            navRow.add(navToggle("AUTH", "AUTH", false, navGroup));
            navRow.add(navToggle("Identity", "IDENTITY", false, navGroup));
            navRow.add(navToggle("Objects", "OBJECTS", false, navGroup));
            navRow.add(navToggle("Security headers", "SECURITY", false, navGroup));
            navPrev.setFocusable(false);
            navNext.setFocusable(false);
            navPrev.setMargin(new Insets(1, 7, 1, 7));
            navNext.setMargin(new Insets(1, 7, 1, 7));
            navPrev.setToolTipText("Elemento interesante anterior");
            navNext.setToolTipText("Siguiente elemento interesante");
            navPrev.addActionListener(e -> navigate(-1));
            navNext.addActionListener(e -> navigate(1));
            navStatus.setFont(navStatus.getFont().deriveFont(Font.PLAIN, 10f));
            navStatus.setForeground(uiColor("Label.disabledForeground", new Color(100, 108, 116)));
            navRow.add(Box.createHorizontalStrut(4));
            navRow.add(navPrev);
            navRow.add(navNext);
            navRow.add(navStatus);
            header.add(navRow);

            http.setEditable(false);
            http.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
            http.setMargin(new Insets(10, 12, 14, 12));
            http.setBorder(BorderFactory.createEmptyBorder());
            http.setBackground(uiColor("TextPane.background", new Color(245, 247, 249)));
            http.setForeground(uiColor("TextPane.foreground", new Color(28, 33, 38)));
            scroll = new JScrollPane(http);
            scroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
            scroll.setBorder(BorderFactory.createMatteBorder(1, 0, 0, 0, uiColor("Separator.foreground", new Color(210, 214, 218))));

            add(header, BorderLayout.NORTH);
            add(scroll, BorderLayout.CENTER);
        }

        private void configureViewToggle(JToggleButton b) {
            b.setFocusable(false);
            b.setMargin(new Insets(1, 7, 1, 7));
            b.setFont(b.getFont().deriveFont(Font.PLAIN, 10f));
        }

        private JToggleButton navToggle(String text, String filter, boolean selected, ButtonGroup group) {
            JToggleButton b = new JToggleButton(text, selected);
            b.setFocusable(false);
            b.setMargin(new Insets(1, 7, 1, 7));
            b.setFont(b.getFont().deriveFont(Font.PLAIN, 10f));
            group.add(b);
            b.addActionListener(e -> {
                navFilter = filter;
                rebuildNavigation();
            });
            return b;
        }

        private void navigate(int delta) {
            if (navAnchors.isEmpty()) return;
            if (navIndex < 0) navIndex = delta >= 0 ? 0 : navAnchors.size() - 1;
            else navIndex = Math.floorMod(navIndex + delta, navAnchors.size());
            int pos = navAnchors.get(navIndex);
            int docLen = http.getDocument().getLength();
            pos = Math.max(0, Math.min(pos, docLen));
            int end = navigationHighlightEnd(pos);
            final int targetPos = pos;
            try {
                Highlighter highlighter = http.getHighlighter();
                if (navHighlightTag != null) {
                    try { highlighter.removeHighlight(navHighlightTag); } catch (Exception ignored) {}
                    navHighlightTag = null;
                }
                if (end > pos) {
                    navHighlightTag = highlighter.addHighlight(pos, end,
                            new DefaultHighlighter.DefaultHighlightPainter(new Color(255, 224, 112)));
                }
            } catch (Exception ignored) {}

            http.requestFocusInWindow();
            http.setCaretPosition(targetPos);
            SwingUtilities.invokeLater(() -> {
                try {
                    Rectangle2D r = http.modelToView2D(targetPos);
                    if (r != null) {
                        Rectangle visible = http.getVisibleRect();
                        int targetY = Math.max(0, (int) r.getY() - Math.max(24, visible.height / 3));
                        http.scrollRectToVisible(new Rectangle(0, targetY, Math.max(1, http.getWidth()), Math.max(1, visible.height)));
                    }
                } catch (Exception ignored) {}
            });
            Timer clear = new Timer(1200, e -> {
                if (navHighlightTag != null) {
                    try { http.getHighlighter().removeHighlight(navHighlightTag); } catch (Exception ignored) {}
                    navHighlightTag = null;
                }
            });
            clear.setRepeats(false);
            clear.start();
            updateNavStatus();
        }

        private int navigationHighlightEnd(int pos) {
            try {
                String rendered = http.getDocument().getText(0, http.getDocument().getLength());
                if (pos < 0 || pos >= rendered.length()) return Math.min(rendered.length(), pos + 1);
                int lineEnd = rendered.indexOf('\n', pos);
                if (lineEnd < 0) lineEnd = rendered.length();
                int badgeEnd = rendered.indexOf('⟧', pos);
                if (badgeEnd >= pos && badgeEnd < lineEnd) return Math.min(rendered.length(), badgeEnd + 1);
                int colon = rendered.indexOf(':', pos);
                if (colon >= pos && colon < lineEnd && colon - pos < 80) return colon + 1;
                return Math.min(lineEnd, pos + 48);
            } catch (Exception ignored) {
                return Math.min(http.getDocument().getLength(), pos + 1);
            }
        }

        private void updateNavStatus() {
            if (navAnchors.isEmpty()) navStatus.setText("0 elementos");
            else if (navIndex < 0) navStatus.setText(navAnchors.size() + " elementos");
            else navStatus.setText((navIndex + 1) + " / " + navAnchors.size());
            navPrev.setEnabled(!navAnchors.isEmpty());
            navNext.setEnabled(!navAnchors.isEmpty());
        }

        private void rebuildNavigation() {
            navAnchors.clear();
            navIndex = -1;
            try {
                String rendered = http.getDocument().getText(0, http.getDocument().getLength());
                if (!"SECURITY".equals(navFilter)) {
                    Pattern badgePattern = switch (navFilter) {
                        case "AUTH" -> Pattern.compile("⟦AUTH(?:\\s|\\u00b7|[^⟧])*⟧", Pattern.CASE_INSENSITIVE);
                        case "IDENTITY" -> Pattern.compile("⟦(?:AUTH|RESOLVER|CONTEXT)(?:\\s|\\u00b7|[^⟧])*⟧", Pattern.CASE_INSENSITIVE);
                        case "OBJECTS" -> Pattern.compile("⟦ENTITY(?:\\s|\\u00b7|[^⟧])*⟧", Pattern.CASE_INSENSITIVE);
                        default -> Pattern.compile("⟦(?:AUTH|RESOLVER|CONTEXT|ENTITY)(?:\\s|\\u00b7|[^⟧])*⟧", Pattern.CASE_INSENSITIVE);
                    };
                    Matcher bm = badgePattern.matcher(rendered);
                    while (bm.find()) navAnchors.add(bm.start());
                }
                if ("ALL".equals(navFilter) || "SECURITY".equals(navFilter)) {
                    Matcher hm = Pattern.compile("(?m)^([!#$%&'*+.^_`|~0-9A-Za-z-]+):").matcher(rendered);
                    while (hm.find()) {
                        String name = hm.group(1).toLowerCase();
                        if (SECURITY_HEADERS.contains(name)) navAnchors.add(hm.start(1));
                    }
                }
                navAnchors.sort(Integer::compareTo);
                for (int i = navAnchors.size() - 1; i > 0; i--) {
                    if (Math.abs(navAnchors.get(i) - navAnchors.get(i - 1)) < 3) navAnchors.remove(i);
                }
            } catch (Exception ignored) {}
            updateNavStatus();
        }

        private JLabel chip(String text, Color background, Color foreground) {
            JLabel label = new JLabel(text == null ? "" : text);
            label.setOpaque(true);
            label.setBackground(background);
            label.setForeground(foreground);
            label.setFont(label.getFont().deriveFont(Font.BOLD, 10f));
            label.setBorder(BorderFactory.createCompoundBorder(
                    BorderFactory.createLineBorder(background.darker(), 1, true),
                    BorderFactory.createEmptyBorder(2, 7, 2, 7)));
            return label;
        }

        private void resetMeta() {
            metaRow.removeAll();
            metaRow.revalidate();
            metaRow.repaint();
        }

        void showLoading() {
            inspectorUrl = "";
            openButton.setEnabled(false);
            endpoint.setText("Consultando evidencia aprendida…");
            resetMeta();
            setPlainDocument("Cargando contexto de Negro…");
        }

        void showError(String message) {
            inspectorUrl = "";
            openButton.setEnabled(false);
            endpoint.setText("No se pudo cargar el contexto");
            resetMeta();
            metaRow.add(chip("OFFLINE", new Color(248, 222, 222), new Color(128, 34, 34)));
            setPlainDocument(message == null ? "Negro no disponible." : message);
        }

        void showContext(String json, String side) {
            String text = decodeB64(jsonString(json, "response".equals(side) ? "response_text_b64" : "request_text_b64"));
            String marks = jsonString(json, "response".equals(side) ? "response_marks_b64" : "request_marks_b64");
            List<ContextMark> decoded = decodeContextMarks(marks);
            String project = jsonString(json, "target_key");
            long exchangeId = jsonLong(json, "exchange_id");
            String method = jsonString(json, "method");
            String path = jsonString(json, "path");
            String host = jsonString(json, "host");
            String env = jsonString(json, "environment");
            String scope = jsonString(json, "scope");
            String match = jsonString(json, "match_kind");
            String identities = jsonString(json, "identity_summary");
            inspectorUrl = jsonString(json, "inspector_url");
            openButton.setEnabled(inspectorUrl != null && !inspectorUrl.isBlank());

            String endpointText = (method == null ? "" : method) + " " + (path == null ? "" : path);
            if (host != null && !host.isBlank()) endpointText += "  ·  " + host;
            endpoint.setText(endpointText.trim());
            resetMeta();
            metaRow.add(chip(project == null || project.isBlank() ? "PROJECT" : project, new Color(231, 235, 239), new Color(55, 62, 69)));
            if (exchangeId > 0) metaRow.add(chip("Request #" + exchangeId, new Color(231, 235, 239), new Color(55, 62, 69)));
            if (identities != null && !identities.isBlank()) metaRow.add(chip(identities, new Color(221, 236, 252), new Color(31, 74, 119)));
            metaRow.add(chip(env == null ? "UNKNOWN" : env, new Color(236, 232, 248), new Color(73, 54, 116)));
            boolean inScope = scope != null && scope.equalsIgnoreCase("IN_SCOPE");
            metaRow.add(chip(scope == null ? "UNKNOWN" : scope,
                    inScope ? new Color(223, 244, 228) : new Color(244, 232, 220),
                    inScope ? new Color(30, 102, 51) : new Color(128, 78, 25)));
            if (match != null && !match.isBlank() && !"exact-bytes".equalsIgnoreCase(match))
                metaRow.add(chip("MATCH · " + match, new Color(238, 240, 242), new Color(82, 88, 94)));
            setSourceHttp(text, decoded);
        }

        private SimpleAttributeSet markStyle(String kind) {
            String k = kind == null ? "" : kind.toLowerCase();
            SimpleAttributeSet a = new SimpleAttributeSet();
            StyleConstants.setBold(a, true);
            switch (k) {
                case "auth" -> {
                    StyleConstants.setBackground(a, new Color(211, 239, 199));
                    StyleConstants.setForeground(a, new Color(35, 82, 25));
                }
                case "resolver" -> {
                    StyleConstants.setBackground(a, new Color(208, 231, 250));
                    StyleConstants.setForeground(a, new Color(26, 75, 116));
                    StyleConstants.setUnderline(a, true);
                }
                case "context" -> {
                    StyleConstants.setBackground(a, new Color(231, 218, 247));
                    StyleConstants.setForeground(a, new Color(83, 49, 123));
                }
                case "entity" -> {
                    StyleConstants.setBackground(a, new Color(250, 226, 199));
                    StyleConstants.setForeground(a, new Color(121, 70, 20));
                }
                default -> {
                    StyleConstants.setBackground(a, new Color(231, 235, 239));
                    StyleConstants.setForeground(a, new Color(55, 62, 69));
                }
            }
            return a;
        }

        private SimpleAttributeSet badgeStyle(String kind) {
            SimpleAttributeSet a = markStyle(kind);
            StyleConstants.setFontSize(a, 9);
            StyleConstants.setUnderline(a, false);
            return a;
        }

        private SimpleAttributeSet style(Color foreground, Color background, boolean bold) {
            SimpleAttributeSet a = new SimpleAttributeSet();
            if (foreground != null) StyleConstants.setForeground(a, foreground);
            if (background != null) StyleConstants.setBackground(a, background);
            StyleConstants.setBold(a, bold);
            return a;
        }

        private int bodyStart(String text) {
            int crlf = text.indexOf("\r\n\r\n");
            if (crlf >= 0) return crlf + 4;
            int lf = text.indexOf("\n\n");
            return lf >= 0 ? lf + 2 : text.length();
        }

        private void applyHttpSyntax(StyledDocument doc, String text) {
            if (text == null || text.isEmpty()) return;
            int body = bodyStart(text);
            SimpleAttributeSet startLine = style(new Color(48, 58, 68), null, true);
            SimpleAttributeSet headerKey = style(new Color(91, 68, 157), null, true);
            SimpleAttributeSet headerValue = style(new Color(66, 73, 80), null, false);
            SimpleAttributeSet securityLine = style(null, new Color(255, 249, 226), false);
            SimpleAttributeSet securityKey = style(new Color(164, 96, 16), new Color(255, 243, 204), true);
            SimpleAttributeSet jsonString = style(new Color(157, 105, 24), null, false);
            SimpleAttributeSet jsonKey = style(new Color(33, 112, 72), null, true);
            SimpleAttributeSet jsonPrimitive = style(new Color(72, 91, 165), null, true);

            int firstNl = text.indexOf('\n');
            if (firstNl < 0) firstNl = Math.min(text.length(), body);
            if (firstNl > 0) doc.setCharacterAttributes(0, firstNl, startLine, false);

            Matcher headers = Pattern.compile("(?m)^([!#$%&'*+.^_`|~0-9A-Za-z-]+):(.*)$").matcher(text.substring(0, body));
            while (headers.find()) {
                int lineStart = headers.start();
                int lineEnd = headers.end();
                int keyStart = headers.start(1);
                int keyEnd = headers.end(1);
                int valueStart = headers.start(2);
                String name = headers.group(1).toLowerCase();
                if (SECURITY_HEADERS.contains(name)) {
                    doc.setCharacterAttributes(lineStart, Math.max(0, lineEnd - lineStart), securityLine, false);
                    doc.setCharacterAttributes(keyStart, keyEnd - keyStart, securityKey, false);
                } else {
                    doc.setCharacterAttributes(keyStart, keyEnd - keyStart, headerKey, false);
                }
                if (lineEnd > valueStart) doc.setCharacterAttributes(valueStart, lineEnd - valueStart, headerValue, false);
            }

            if (body < text.length()) {
                String bodyText = text.substring(body);
                Matcher strings = Pattern.compile("\"(?:\\\\.|[^\"\\\\])*\"").matcher(bodyText);
                while (strings.find()) {
                    doc.setCharacterAttributes(body + strings.start(), strings.end() - strings.start(), jsonString, false);
                }
                Matcher keys = Pattern.compile("\"(?:\\\\.|[^\"\\\\])*\"(?=\\s*:)").matcher(bodyText);
                while (keys.find()) {
                    doc.setCharacterAttributes(body + keys.start(), keys.end() - keys.start(), jsonKey, false);
                }
                Matcher primitives = Pattern.compile("(?<![A-Za-z0-9_])(?:true|false|null|-?\\d+(?:\\.\\d+)?)(?![A-Za-z0-9_])", Pattern.CASE_INSENSITIVE).matcher(bodyText);
                while (primitives.find()) {
                    doc.setCharacterAttributes(body + primitives.start(), primitives.end() - primitives.start(), jsonPrimitive, false);
                }
            }
        }

        private void setPlainDocument(String text) {
            sourceHttpText = "";
            sourceHttpMarks = List.of();
            setDocumentText(text, List.of());
        }

        private void setSourceHttp(String text, List<ContextMark> marks) {
            sourceHttpText = text == null ? "" : text;
            sourceHttpMarks = marks == null ? List.of() : List.copyOf(marks);
            renderSourceHttp();
        }

        private void renderSourceHttp() {
            if (sourceHttpText == null || sourceHttpText.isEmpty()) {
                setDocumentText("", List.of());
                return;
            }
            RenderedHttp rendered = prettyMode ? prettyHttp(sourceHttpText, sourceHttpMarks)
                    : new RenderedHttp(sourceHttpText, sourceHttpMarks);
            setDocumentText(rendered.text(), rendered.marks());
        }

        private RenderedHttp prettyHttp(String raw, List<ContextMark> marks) {
            if (raw == null || raw.isEmpty()) return new RenderedHttp("", List.of());
            int body = bodyStart(raw);
            if (body >= raw.length()) return new RenderedHttp(raw, marks == null ? List.of() : marks);
            String bodyText = raw.substring(body);
            int first = 0;
            while (first < bodyText.length() && Character.isWhitespace(bodyText.charAt(first))) first++;
            if (first >= bodyText.length() || (bodyText.charAt(first) != '{' && bodyText.charAt(first) != '[') || !looksLikeJson(bodyText.substring(first))) {
                return new RenderedHttp(raw, marks == null ? List.of() : marks);
            }

            StringBuilder out = new StringBuilder(raw.length() + Math.max(64, bodyText.length() / 4));
            int[] boundary = new int[raw.length() + 1];
            for (int i = 0; i <= body; i++) boundary[i] = i;
            out.append(raw, 0, body);

            boolean inString = false;
            boolean escape = false;
            int indent = 0;
            boolean lineStart = false;
            for (int i = body; i < raw.length(); i++) {
                boundary[i] = out.length();
                char c = raw.charAt(i);
                if (inString) {
                    out.append(c);
                    if (escape) escape = false;
                    else if (c == '\\') escape = true;
                    else if (c == '"') inString = false;
                    boundary[i + 1] = out.length();
                    continue;
                }
                if (c == '"') {
                    if (lineStart) { appendIndent(out, indent); lineStart = false; }
                    out.append(c);
                    inString = true;
                } else if (c == '{' || c == '[') {
                    if (lineStart) { appendIndent(out, indent); lineStart = false; }
                    out.append(c);
                    indent++;
                    out.append('\n');
                    lineStart = true;
                } else if (c == '}' || c == ']') {
                    indent = Math.max(0, indent - 1);
                    trimTrailingSpaces(out);
                    if (out.length() > 0 && out.charAt(out.length() - 1) != '\n') out.append('\n');
                    appendIndent(out, indent);
                    out.append(c);
                    lineStart = false;
                } else if (c == ',') {
                    out.append(c).append('\n');
                    lineStart = true;
                } else if (c == ':') {
                    out.append(c).append(' ');
                    lineStart = false;
                } else if (Character.isWhitespace(c)) {
                    // Pretty view owns whitespace outside strings.
                } else {
                    if (lineStart) { appendIndent(out, indent); lineStart = false; }
                    out.append(c);
                }
                boundary[i + 1] = out.length();
            }
            boundary[raw.length()] = out.length();

            List<ContextMark> mapped = new ArrayList<>();
            for (ContextMark mark : marks == null ? List.<ContextMark>of() : marks) {
                int s = Math.max(0, Math.min(mark.start(), raw.length()));
                int e = Math.max(s, Math.min(mark.end(), raw.length()));
                int ms = boundary[s];
                int me = boundary[e];
                if (me > ms) mapped.add(new ContextMark(ms, me, mark.kind(), mark.label(), mark.reason(), mark.sourceExchangeId()));
            }
            return new RenderedHttp(out.toString(), mapped);
        }

        private boolean looksLikeJson(String text) {
            boolean inString = false;
            boolean escape = false;
            int braces = 0;
            int brackets = 0;
            boolean sawRoot = false;
            for (int i = 0; i < text.length(); i++) {
                char c = text.charAt(i);
                if (inString) {
                    if (escape) escape = false;
                    else if (c == '\\') escape = true;
                    else if (c == '"') inString = false;
                    continue;
                }
                if (c == '"') { inString = true; continue; }
                if (c == '{') { braces++; sawRoot = true; }
                else if (c == '}') { braces--; if (braces < 0) return false; }
                else if (c == '[') { brackets++; sawRoot = true; }
                else if (c == ']') { brackets--; if (brackets < 0) return false; }
            }
            return sawRoot && !inString && braces == 0 && brackets == 0;
        }

        private void appendIndent(StringBuilder out, int indent) {
            out.append("  ".repeat(Math.max(0, indent)));
        }

        private void trimTrailingSpaces(StringBuilder out) {
            while (out.length() > 0) {
                char c = out.charAt(out.length() - 1);
                if (c == ' ' || c == '\t') out.setLength(out.length() - 1);
                else break;
            }
        }

        private void setDocumentText(String text, List<ContextMark> marks) {
            StyledDocument doc = http.getStyledDocument();
            try {
                doc.remove(0, doc.getLength());
                String safe = text == null ? "" : text;
                doc.insertString(0, safe, null);
                applyHttpSyntax(doc, safe);
                List<ContextMark> ordered = new ArrayList<>(marks == null ? List.of() : marks);
                ordered.sort((a,b) -> Integer.compare(b.start(), a.start()));
                for (ContextMark mark : ordered) {
                    int start = Math.max(0, Math.min(mark.start(), safe.length()));
                    int end = Math.max(start, Math.min(mark.end(), safe.length()));
                    if (end <= start) continue;
                    doc.setCharacterAttributes(start, end-start, markStyle(mark.kind()), false);
                    String badge = "  ⟦" + (mark.label() == null || mark.label().isBlank() ? mark.kind().toUpperCase() : mark.label()) + "⟧";
                    doc.insertString(end, badge, badgeStyle(mark.kind()));
                }
                rebuildNavigation();
                http.setCaretPosition(0);
            } catch (BadLocationException ex) {
                http.setText(text == null ? "" : text);
                rebuildNavigation();
            }
        }

        String selectedText() { return http.getSelectedText(); }
    }

    private void loadNegroContextAsync(HttpRequestResponse pair, NegroContextView view, String side) {
        if (pair == null || pair.request() == null) {
            view.showError("Sin Request disponible.");
            return;
        }
        HttpRequest req = pair.request();
        String requestB64 = Base64.getEncoder().encodeToString(req.toByteArray().getBytes());
        String body = req.url() + "\t" + req.method() + "\t" + requestB64;
        view.showLoading();
        java.net.http.HttpRequest httpReq = java.net.http.HttpRequest.newBuilder()
                .uri(URI.create(negroBaseUrl + "/api/bridge/context"))
                .timeout(Duration.ofSeconds(4))
                .header("Content-Type", "text/plain; charset=utf-8")
                .POST(BodyPublishers.ofString(body, StandardCharsets.UTF_8)).build();
        client.sendAsync(httpReq, BodyHandlers.ofString(StandardCharsets.UTF_8))
                .thenAccept(resp -> SwingUtilities.invokeLater(() -> {
                    if (resp.statusCode() == 200 && jsonBoolean(resp.body(), "found", false)) view.showContext(resp.body(), side);
                    else view.showError("Esta Request todavía no tiene evidencia compatible en Negro.");
                }))
                .exceptionally(ex -> {
                    SwingUtilities.invokeLater(() -> view.showError("Negro no disponible: " + ex.getClass().getSimpleName()));
                    return null;
                });
    }

    private final class NegroContextRequestProvider implements HttpRequestEditorProvider {
        @Override
        public ExtensionProvidedHttpRequestEditor provideHttpRequestEditor(EditorCreationContext context) {
            return new ExtensionProvidedHttpRequestEditor() {
                private final NegroContextView view = new NegroContextView();
                private HttpRequest currentRequest;
                @Override public void setRequestResponse(HttpRequestResponse pair) { currentRequest = pair == null ? null : pair.request(); loadNegroContextAsync(pair, view, "request"); }
                @Override public HttpRequest getRequest() { return currentRequest; }
                @Override public boolean isEnabledFor(HttpRequestResponse pair) { return pair != null && pair.request() != null; }
                @Override public String caption() { return "Negro Context"; }
                @Override public Component uiComponent() { return view; }
                @Override public Selection selectedData() { String x=view.selectedText(); return x == null ? null : Selection.selection(ByteArray.byteArray(x.getBytes(StandardCharsets.UTF_8))); }
                @Override public boolean isModified() { return false; }
            };
        }
    }

    private final class NegroContextResponseProvider implements HttpResponseEditorProvider {
        @Override
        public ExtensionProvidedHttpResponseEditor provideHttpResponseEditor(EditorCreationContext context) {
            return new ExtensionProvidedHttpResponseEditor() {
                private final NegroContextView view = new NegroContextView();
                private HttpResponse currentResponse;
                @Override public void setRequestResponse(HttpRequestResponse pair) { currentResponse = pair == null ? null : pair.response(); loadNegroContextAsync(pair, view, "response"); }
                @Override public HttpResponse getResponse() { return currentResponse; }
                @Override public boolean isEnabledFor(HttpRequestResponse pair) { return pair != null && pair.request() != null; }
                @Override public String caption() { return "Negro Context"; }
                @Override public Component uiComponent() { return view; }
                @Override public Selection selectedData() { String x=view.selectedText(); return x == null ? null : Selection.selection(ByteArray.byteArray(x.getBytes(StandardCharsets.UTF_8))); }
                @Override public boolean isModified() { return false; }
            };
        }
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
                    .header("X-Negro-Bridge-Version", "0.39.0")
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
                kv("response_body_b64", responseBodyB64) + "," +
                "\"burp_in_scope\":" + api.scope().isInScope(request.url()) +
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
                kv("response_body_b64", responseBodyB64) + "," +
                "\"burp_in_scope\":" + api.scope().isInScope(request.url()) +
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

    private record IdentityEvidenceChoice(String candidateId, String kind, String type, String name, String preview, String defaultClassification) {
        @Override public String toString() { return type + " · " + name + " · " + preview; }
    }

    private record EvidenceDecision(String candidateId, String classification) {}

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

            JMenu scopeMenu = new JMenu("Scope");
            JMenuItem scopeStatus = new JMenuItem(api.scope().isInScope(selected.get(0).request().url()) ? "Estado: IN_SCOPE" : "Estado: EXCLUDED");
            scopeStatus.setEnabled(false);
            JMenuItem scopeInclude = new JMenuItem("Añadir a Burp + Negro…");
            JMenuItem scopeExclude = new JMenuItem("Excluir host de Burp scope");
            scopeMenu.add(scopeStatus); scopeMenu.addSeparator(); scopeMenu.add(scopeInclude); scopeMenu.add(scopeExclude);

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
            scopeInclude.addActionListener(e -> runContextAction("scope-include", () -> addHostToBurpAndNegro(selected.get(0).request().url())));
            scopeExclude.addActionListener(e -> runContextAction("scope-exclude", () -> setHostBurpScope(selected.get(0).request().url(), false)));
            assignIdentity.addActionListener(e -> runContextAction("identity-assign", () -> assignIdentityFromBurp(selected.get(0), tool)));
            createIdentity.addActionListener(e -> runContextAction("identity-create", () -> createIdentityFromBurp(selected.get(0), tool)));
            updateAuth.addActionListener(e -> runContextAction("identity-update", () -> updateIdentityAuthFromBurp(selected.get(0), tool)));
            sendAs.addActionListener(e -> runContextAction("identity-send", () -> sendAsIdentityFromBurp(selected.get(0), tool)));
            compareIdentity.addActionListener(e -> runContextAction("replay-compare", () -> openReplayChooserFromBurp(selected.get(0), tool)));
            createFinding.addActionListener(e -> runContextAction("finding", () -> createFindingFromBurp(selected.get(0), tool)));
            attachFinding.addActionListener(e -> runContextAction("attach", () -> attachFindingFromBurp(selected.get(0), tool)));
            retest.addActionListener(e -> runContextAction("retest", () -> attachRetestFromBurp(selected.get(0), tool)));
            menu.add(open); menu.add(replayMenu); menu.add(compareIdentity); menu.addSeparator(); menu.add(contextMenu); menu.add(flowMenu); menu.add(identityMenu); menu.add(scopeMenu); menu.add(stateMenu); menu.add(findingMenu);
            return List.of(menu);
        }
    }

    private record NegroProject(String key, String name, List<String> scopes) {
        @Override public String toString() {
            String roots = scopes == null || scopes.isEmpty() ? "sin alcances" : String.join(", ", scopes);
            return name + "  [" + roots + "]";
        }
    }

    private List<NegroProject> loadNegroProjects() {
        try {
            java.net.http.HttpRequest req = java.net.http.HttpRequest.newBuilder()
                    .uri(URI.create(negroBaseUrl + "/api/bridge/projects"))
                    .timeout(Duration.ofSeconds(10)).header("Accept", "text/plain").GET().build();
            java.net.http.HttpResponse<String> resp = client.send(req, BodyHandlers.ofString(StandardCharsets.UTF_8));
            if (resp.statusCode() != 200) throw new IllegalStateException("Negro projects HTTP " + resp.statusCode());
            List<NegroProject> result = new ArrayList<>();
            for (String line : resp.body().split("\\R")) {
                if (line.isBlank()) continue;
                String[] parts = line.split("\\t", -1);
                if (parts.length < 2) continue;
                List<String> roots = new ArrayList<>();
                if (parts.length >= 3 && !parts[2].isBlank()) {
                    for (String root : parts[2].split(",")) if (!root.isBlank()) roots.add(root.trim().toLowerCase());
                }
                result.add(new NegroProject(parts[0].trim(), parts[1].trim(), roots));
            }
            return result;
        } catch (Exception ex) {
            throw new IllegalStateException("No pude cargar los proyectos de Negro: " + ex.getMessage(), ex);
        }
    }

    private NegroProject chooseNegroProject(String host, List<NegroProject> projects) {
        if (projects == null || projects.isEmpty()) throw new IllegalStateException("No hay proyectos creados en Negro");
        final NegroProject[] selected = new NegroProject[1];
        Runnable chooser = () -> {
            Object value = JOptionPane.showInputDialog(
                    null,
                    "¿A qué proyecto de Negro pertenece " + host + "?",
                    "Negro · Asignar alcance",
                    JOptionPane.QUESTION_MESSAGE,
                    null,
                    projects.toArray(),
                    projects.get(0));
            if (value instanceof NegroProject p) selected[0] = p;
        };
        try {
            if (SwingUtilities.isEventDispatchThread()) chooser.run(); else SwingUtilities.invokeAndWait(chooser);
        } catch (Exception ex) {
            throw new IllegalStateException("No pude abrir el selector de proyecto", ex);
        }
        return selected[0];
    }

    private String hostFromUrl(String observedUrl) {
        try {
            URI u = URI.create(observedUrl);
            return u.getHost() == null ? "" : u.getHost().toLowerCase();
        } catch (Exception ex) { return ""; }
    }

    private boolean hostMatchesProjectScope(String host, String root) {
        String h = host == null ? "" : host.toLowerCase().replaceAll("\\.$", "");
        String r = root == null ? "" : root.toLowerCase().replaceAll("^https?://", "").replaceAll("/.*$", "").replaceAll("\\.$", "");
        return !h.isBlank() && !r.isBlank() && (h.equals(r) || h.endsWith("." + r));
    }

    private void assignHostToNegroProject(String host, NegroProject project) {
        try {
            String payload = project.key() + "\t" + host;
            java.net.http.HttpRequest req = java.net.http.HttpRequest.newBuilder()
                    .uri(URI.create(negroBaseUrl + "/api/bridge/project-scope"))
                    .timeout(Duration.ofSeconds(10))
                    .header("Content-Type", "text/plain; charset=utf-8")
                    .POST(BodyPublishers.ofString(payload, StandardCharsets.UTF_8)).build();
            java.net.http.HttpResponse<String> resp = client.send(req, BodyHandlers.ofString(StandardCharsets.UTF_8));
            if (resp.statusCode() < 200 || resp.statusCode() >= 300) {
                throw new IllegalStateException("Negro respondió HTTP " + resp.statusCode() + " · " + resp.body());
            }
            api.logging().logToOutput("Negro scope → " + host + " asignado a proyecto " + project.name());
        } catch (Exception ex) {
            throw new IllegalStateException("No pude agregar el alcance al proyecto Negro: " + ex.getMessage(), ex);
        }
    }

    private void addHostToBurpAndNegro(String observedUrl) {
        String host = hostFromUrl(observedUrl);
        if (host.isBlank()) throw new IllegalStateException("No pude determinar el host seleccionado");
        List<NegroProject> projects = loadNegroProjects();
        NegroProject project = chooseNegroProject(host, projects);
        if (project == null) return; // investigator cancelled
        assignHostToNegroProject(host, project);
        setHostBurpScope(observedUrl, true);
        showMessage("Negro", host + " quedó IN_SCOPE en Burp y asociado a " + project.name() + ".", JOptionPane.INFORMATION_MESSAGE);
    }

    private void promptUnassignedInScopeHosts() {
        if (unloading.get()) return;
        try {
            List<NegroProject> projects = loadNegroProjects();
            if (projects.isEmpty()) return;
            Set<String> inScopeHosts = new java.util.LinkedHashSet<>();
            for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
                if (rr == null || rr.request() == null) continue;
                String url = rr.request().url();
                if (url == null || url.isBlank() || isNegroBridgeTraffic(url)) continue;
                try {
                    if (!api.scope().isInScope(url)) continue;
                } catch (Exception ex) { continue; }
                String host = hostFromUrl(url);
                if (!host.isBlank()) inScopeHosts.add(host);
            }
            List<String> unknown = new ArrayList<>();
            for (String host : inScopeHosts) {
                boolean assigned = false;
                for (NegroProject p : projects) {
                    for (String root : p.scopes()) {
                        if (hostMatchesProjectScope(host, root)) { assigned = true; break; }
                    }
                    if (assigned) break;
                }
                if (!assigned && scopeHostsAlreadyPrompted.add(host)) unknown.add(host);
            }
            if (unknown.isEmpty()) return;
            if (unknown.size() > 5) {
                showMessage("Negro · Scope", unknown.size() + " hosts quedaron in-scope en Burp sin proyecto Negro. Usa clic derecho → Negro → Scope → Añadir a Burp + Negro… para asignarlos.", JOptionPane.WARNING_MESSAGE);
                return;
            }
            for (String host : unknown) {
                NegroProject project = chooseNegroProject(host, projects);
                if (project != null) assignHostToNegroProject(host, project);
            }
            reconcileBurpScope("native-scope-assignment");
        } catch (Throwable ex) {
            api.logging().logToError("Negro scope project chooser: " + (ex.getMessage() == null ? ex.getClass().getSimpleName() : ex.getMessage()));
        }
    }

    private void setHostBurpScope(String observedUrl, boolean include) {
        try {
            URI u = URI.create(observedUrl);
            String scheme = u.getScheme() == null ? "https" : u.getScheme();
            int port = u.getPort();
            boolean defaultPort = port < 0 || ("https".equalsIgnoreCase(scheme) && port == 443) || ("http".equalsIgnoreCase(scheme) && port == 80);
            String base = scheme + "://" + u.getHost() + (defaultPort ? "" : ":" + port) + "/";
            if (include) api.scope().includeInScope(base); else api.scope().excludeFromScope(base);
            api.logging().logToOutput("Negro scope → " + (include ? "include " : "exclude ") + base);
            reconcileBurpScopeAsync(include ? "menu-include" : "menu-exclude");
        } catch (Exception ex) {
            throw new IllegalStateException("No pude actualizar Burp scope: " + ex.getMessage(), ex);
        }
    }

    private void reconcileBurpScopeAsync(String reason) {
        bridgePoller.execute(() -> reconcileBurpScope(reason));
    }

    private void reconcileBurpScope(String reason) {
        if (unloading.get()) return;
        try {
            java.net.http.HttpRequest req = java.net.http.HttpRequest.newBuilder()
                    .uri(URI.create(negroBaseUrl + "/api/bridge/scope/candidates"))
                    .timeout(Duration.ofSeconds(10)).header("Accept", "text/plain").GET().build();
            java.net.http.HttpResponse<String> resp = client.send(req, BodyHandlers.ofString(StandardCharsets.UTF_8));
            if (resp.statusCode() != 200) return;
            StringBuilder body = new StringBuilder();
            int candidates = 0;
            for (String line : resp.body().split("\\R")) {
                if (line.isBlank()) continue;
                int tab = line.indexOf('\t');
                if (tab <= 0 || tab >= line.length() - 1) continue;
                String targetKey = line.substring(0, tab);
                String url = line.substring(tab + 1).trim();
                if (url.isBlank()) continue;
                boolean inScope;
                try { inScope = api.scope().isInScope(url); } catch (Exception ex) { continue; }
                body.append(targetKey).append('\t').append(inScope ? "IN_SCOPE" : "EXCLUDED").append('\t').append(url).append('\n');
                candidates++;
            }
            if (candidates == 0) return;
            java.net.http.HttpRequest sync = java.net.http.HttpRequest.newBuilder()
                    .uri(URI.create(negroBaseUrl + "/api/bridge/scope/sync"))
                    .timeout(Duration.ofSeconds(15)).header("Content-Type", "text/plain; charset=utf-8")
                    .POST(BodyPublishers.ofString(body.toString(), StandardCharsets.UTF_8)).build();
            java.net.http.HttpResponse<String> synced = client.send(sync, BodyHandlers.ofString(StandardCharsets.UTF_8));
            if (synced.statusCode() >= 200 && synced.statusCode() < 300) lastScopeReconcileMs.set(System.currentTimeMillis());
            api.logging().logToOutput("Negro scope sync · " + reason + " · URLs=" + candidates + " · HTTP " + synced.statusCode());
        } catch (Throwable ex) {
            api.logging().logToError("Negro scope sync falló · " + reason + " · " + (ex.getMessage() == null ? ex.getClass().getSimpleName() : ex.getMessage()));
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

    private List<IdentityEvidenceChoice> identityEvidenceChoices(String targetKey, long exchangeId) {
        try {
            String json = getText("/api/bridge/auth-materials/" + targetKey + "/" + exchangeId);
            List<IdentityEvidenceChoice> out = new ArrayList<>();
            Pattern p = Pattern.compile("\"candidate_id\":\"((?:\\\\.|[^\"\\\\])*)\".*?\"kind\":\"([^\"]+)\".*?\"material_type\":\"([^\"]+)\".*?\"name\":\"((?:\\\\.|[^\"\\\\])*)\".*?\"preview\":\"((?:\\\\.|[^\"\\\\])*)\".*?\"default_classification\":\"([^\"]+)\"", Pattern.DOTALL);
            Matcher m = p.matcher(json);
            while (m.find()) out.add(new IdentityEvidenceChoice(unescapeJson(m.group(1)), m.group(2), m.group(3), unescapeJson(m.group(4)), unescapeJson(m.group(5)), m.group(6)));
            return out;
        } catch (Exception ex) { throw new IllegalStateException(ex); }
    }

    private List<EvidenceDecision> chooseIdentityEvidence(String targetKey, long exchangeId, String title) {
        List<IdentityEvidenceChoice> candidates = identityEvidenceChoices(targetKey, exchangeId);
        if (candidates.isEmpty()) { showMessage("Negro", "No detecté material de sesión/identidad en esta request.", JOptionPane.INFORMATION_MESSAGE); return null; }
        JPanel panel = formPanel();
        panel.add(new JLabel("Clasifica cada dato. Sólo AUTH/RESOLVER participan en atribución automática:"));
        List<JComboBox<String>> combos = new ArrayList<>();
        String[] options = new String[]{"AUTH", "RESOLVER", "CONTEXT", "IGNORE"};
        for (IdentityEvidenceChoice candidate : candidates) {
            panel.add(new JLabel(candidate.toString()));
            JComboBox<String> combo = new JComboBox<>(options);
            String wanted = candidate.defaultClassification().toUpperCase();
            combo.setSelectedItem(wanted);
            combos.add(combo); panel.add(combo);
        }
        if (confirmDialog(title, panel) != JOptionPane.OK_OPTION) return null;
        List<EvidenceDecision> out = new ArrayList<>();
        for (int i = 0; i < candidates.size(); i++) out.add(new EvidenceDecision(candidates.get(i).candidateId(), String.valueOf(combos.get(i).getSelectedItem()).toLowerCase()));
        return out;
    }

    private String encodeEvidenceDecisions(List<EvidenceDecision> decisions) {
        if (decisions == null) return "";
        List<String> parts = new ArrayList<>();
        for (EvidenceDecision d : decisions) parts.add(d.candidateId() + "=" + d.classification());
        return String.join("|", parts);
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
        List<EvidenceDecision> decisions = chooseIdentityEvidence(ctx.targetKey(), ctx.exchangeId(), "Create Identity · clasificar evidencia");
        if (decisions == null) return;
        JTextField name = new JTextField(32);
        JPanel panel = formPanel(); panel.add(new JLabel("Nombre de la identidad")); panel.add(name);
        if (confirmDialog("Create Identity from this request", panel) != JOptionPane.OK_OPTION) return;
        String identityName = name.getText().trim(); if (identityName.isEmpty()) return;
        try {
            String extra = kv("name", identityName) + "," + kv("evidence_decisions", encodeEvidenceDecisions(decisions));
            String body = postBridgeAction(ctx, "identity_create", extra);
            long id = jsonLong(body, "identity_id");
            appendNegroNote(rr.annotations(), "NEGRO · IDENTITY · " + identityName);
            showMessage("Negro", "Identity #" + id + " creada y asociada al exchange #" + ctx.exchangeId(), JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ex) { throw new IllegalStateException(ex); }
    }

    private void updateIdentityAuthFromBurp(HttpRequestResponse rr, String tool) {
        BridgeContext ctx = ingestContext(rr, tool);
        IdentityChoice choice = chooseIdentity(ctx.targetKey(), "Update auth material", false); if (choice == null) return;
        List<EvidenceDecision> decisions = chooseIdentityEvidence(ctx.targetKey(), ctx.exchangeId(), "Clasificar evidencia actual de " + choice.label());
        if (decisions == null) return;
        try {
            String extra = "\"identity_id\":" + choice.identityId() + ",\"context_id\":" + (choice.contextId() > 0 ? Long.toString(choice.contextId()) : "null") + "," + kv("evidence_decisions", encodeEvidenceDecisions(decisions));
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
