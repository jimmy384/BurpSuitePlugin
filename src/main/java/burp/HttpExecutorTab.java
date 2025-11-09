package burp;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import javax.net.ssl.*;
import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

public class HttpExecutorTab implements ITab {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;


    private JPanel mainPanel;
    private JButton btnLoad, btnRun;
    private JTextArea logArea;
    private JTextArea configView;
    private JLabel lblTotal, lblInProgress, lblRemaining, lblSuccess, lblFail;

    private File configFile;
    private File resultsDir;
    private Config configObj;
    private ExecutorService executor;

    // progress counters
    private final AtomicInteger total = new AtomicInteger(0);
    private final AtomicInteger inProgress = new AtomicInteger(0);
    private final AtomicInteger successCount = new AtomicInteger(0);
    private final AtomicInteger failCount = new AtomicInteger(0);

    public HttpExecutorTab(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
    }

    public void buildUi() {
        mainPanel = new JPanel(new BorderLayout(8, 8));
        mainPanel.setBorder(new EmptyBorder(8, 8, 8, 8));

        // top controls
        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JTextField configFilePathTextField = new JTextField();
        configFilePathTextField.setColumns(50);
        btnLoad = new JButton("加载配置");
        btnRun = new JButton("执行");
        top.add(configFilePathTextField);
        top.add(btnLoad);
        top.add(btnRun);

        mainPanel.add(top, BorderLayout.NORTH);

        // center split: left config, right logs/progress
        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        split.setResizeWeight(0.4);

        configView = new JTextArea();
        configView.setEditable(false);
        JScrollPane cfgScroll = new JScrollPane(configView);
        cfgScroll.setBorder(BorderFactory.createTitledBorder("config.json"));

        JPanel right = new JPanel(new BorderLayout(8, 8));
        logArea = new JTextArea();
        logArea.setEditable(false);
        JScrollPane logScroll = new JScrollPane(logArea);
        logScroll.setBorder(BorderFactory.createTitledBorder("Log"));

        // progress panel
        JPanel prog = new JPanel(new GridLayout(2, 3, 6, 6));
        lblTotal = new JLabel("总数: 0");
        lblInProgress = new JLabel("进行中: 0");
        lblRemaining = new JLabel("剩余: 0");
        lblSuccess = new JLabel("成功: 0");
        lblFail = new JLabel("失败: 0");
        prog.add(lblTotal);
        prog.add(lblInProgress);
        prog.add(lblRemaining);
        prog.add(lblSuccess);
        prog.add(lblFail);

        right.add(prog, BorderLayout.NORTH);
        right.add(logScroll, BorderLayout.CENTER);

        split.setLeftComponent(cfgScroll);
        split.setRightComponent(right);

        mainPanel.add(split, BorderLayout.CENTER);

        // button actions
        btnLoad.addActionListener(e -> {
            String configFilePath = configFilePathTextField.getText();
            if (configFilePath != null && !configFilePath.isEmpty()) {
                configFile = new File(configFilePath);
            } else {
                JFileChooser chooser = new JFileChooser();
                chooser.setDialogTitle("选择配置文件config.json");
                chooser.setFileFilter(new FileNameExtensionFilter("JSON files", "json"));
                int ret = chooser.showOpenDialog(mainPanel);
                if (ret == JFileChooser.APPROVE_OPTION) {
                    configFile = chooser.getSelectedFile();
                }
            }
            resultsDir = new File(configFile.getParentFile(), "results");
            resultsDir.mkdirs();
            loadConfigAndShow();
        });

        btnRun.addActionListener(e -> {
            if (configObj == null) {
                appendLog("配置文件未加载");
                loadConfigAndShow();
                if (configObj == null) {
                    appendLog("配置文件未加载");
                    return;
                }
            }
            startRun();
        });
    }

    private void loadConfigAndShow() {
        try {
            if (configFile == null) {
                appendLog("请先用Load Config功能加载配置文件");
                return;
            }
            if (!configFile.exists()) {
                appendLog("配置文件不存在: " + configFile.getAbsolutePath());
                configView.setText("");
                configObj = null;
                return;
            }
            String raw = readFile(configFile);
            configView.setText(raw);
            Gson gson = new GsonBuilder().setPrettyPrinting().create();
            configObj = gson.fromJson(raw, Config.class);
            appendLog("加载配置文件成功: " + configFile.getAbsolutePath());
        } catch (Exception ex) {
            appendLog("加载配置文件失败: " + ex.getMessage());
            configObj = null;
        }
    }

    private static String readFile(File f) throws IOException {
        try (FileInputStream fis = new FileInputStream(f)) {
            byte[] b = new byte[(int) f.length()];
            fis.read(b);
            fis.close();
            return new String(b, StandardCharsets.UTF_8);
        }
    }

    private void startRun() {
        // reset counters
        total.set(0);
        inProgress.set(0);
        successCount.set(0);
        failCount.set(0);
        updateProgressLabels();

        if (executor != null && !executor.isShutdown()) {
            executor.shutdownNow();
        }
        int concurrency = (configObj != null && configObj.concurrency != null && configObj.concurrency > 0) ? configObj.concurrency : 5;
        executor = Executors.newFixedThreadPool(concurrency);

        // prepare list of enabled interfaces
        final List<InterfaceItem> interfaces = (configObj != null && configObj.interfaces != null) ? configObj.interfaces : Collections.emptyList();
        final boolean globalEnabled = (configObj == null) ? true : (configObj.enabled == null ? true : configObj.enabled);
        final List<Integer> enabledIndexes = new ArrayList<>();
        for (int i = 0; i < interfaces.size(); i++) {
            InterfaceItem it = interfaces.get(i);
            boolean enabled = (it.enabled == null) ? globalEnabled : it.enabled;
            if (enabled) enabledIndexes.add(i);
        }
        total.set(enabledIndexes.size());
        updateProgressLabels();

        appendLog("Starting run: total enabled interfaces = " + total.get());

        // results array to preserve order
        final Object[] results = new Object[interfaces.size()];

        // submit tasks using index queue
        final BlockingQueue<Integer> queue = new LinkedBlockingQueue<>(enabledIndexes);
        final long globalTimeout = (configObj != null && configObj.timeoutMs != null) ? configObj.timeoutMs : 10000L;
        final Map<String, String> globalHeaders = (configObj != null && configObj.headers != null) ? configObj.headers : new HashMap<>();

        final CountDownLatch latch = new CountDownLatch(enabledIndexes.size());

        // determine whether to send to upstream proxy listener (so Burp Proxy can intercept it)
        final boolean useUpstreamProxy = (configObj != null && configObj.burpProxyHost != null && configObj.burpProxyHost.trim().length() > 0);

        for (int t = 0; t < concurrency; t++) {
            executor.submit(() -> {
                while (true) {
                    Integer idx = queue.poll();
                    if (idx == null) break;
                    InterfaceItem it = interfaces.get(idx);

                    // update in-progress
                    inProgress.incrementAndGet();
                    updateProgressLabels();

                    try {
                        // merge headers
                        Map<String, String> headersMerged = new HashMap<>(globalHeaders);
                        if (it.headers != null) headersMerged.putAll(it.headers);

                        // build request bytes: for proxy-socket mode need absolute-form
                        byte[] requestBytes;
                        if (useUpstreamProxy) {
                            requestBytes = buildRequestBytes(it, headersMerged, true); // absolute-form
                        } else {
                            requestBytes = buildRequestBytes(it, headersMerged, false);
                        }

                        // perform request via chosen method
                        if (useUpstreamProxy) {
                            String proxyHost = configObj.burpProxyHost;
                            int proxyPort = (configObj.burpProxyPort != null) ? configObj.burpProxyPort : 8080;
                            long timeout = (it.timeoutMs != null) ? it.timeoutMs : globalTimeout;

                            // parse target url
                            URL targetUrl = new URL(it.url);
                            String targetHost = targetUrl.getHost();
                            int targetPort = targetUrl.getPort() == -1 ? (targetUrl.getProtocol().equalsIgnoreCase("https") ? 443 : 80) : targetUrl.getPort();
                            boolean targetIsHttps = "https".equalsIgnoreCase(targetUrl.getProtocol());

                            Socket sock = null;
                            try {
                                sock = new Socket();
                                sock.connect(new InetSocketAddress(proxyHost, proxyPort), (int) Math.max(1000, Math.min(timeout, Integer.MAX_VALUE)));
                                sock.setSoTimeout((int) Math.max(1000, Math.min(timeout, Integer.MAX_VALUE)));

                                OutputStream os = sock.getOutputStream();
                                InputStream is = sock.getInputStream();

                                if (targetIsHttps) {
                                    // 1) send CONNECT to proxy
                                    String connectLine = "CONNECT " + targetHost + ":" + targetPort + " HTTP/1.1\r\n" +
                                            "Host: " + targetHost + ":" + targetPort + "\r\n" +
                                            "\r\n";
                                    os.write(connectLine.getBytes(StandardCharsets.UTF_8));
                                    os.flush();

                                    // 2) read proxy response header (simple, read until \r\n\r\n)
                                    ByteArrayOutputStream headerBuf = new ByteArrayOutputStream();
                                    int prev = -1, cur;
                                    long headerStart = System.currentTimeMillis();
                                    boolean headerDone = false;
                                    while (!headerDone && (cur = is.read()) != -1) {
                                        headerBuf.write(cur);
                                        if (headerBuf.size() > 8192) break; // header too big
                                        // check for \r\n\r\n
                                        int len = headerBuf.size();
                                        byte[] hb = headerBuf.toByteArray();
                                        if (len >= 4 &&
                                                hb[len - 4] == '\r' && hb[len - 3] == '\n' && hb[len - 2] == '\r' && hb[len - 1] == '\n') {
                                            headerDone = true;
                                            break;
                                        }
                                        // timeout safety
                                        if (System.currentTimeMillis() - headerStart > timeout) {
                                            appendLog("CONNECT header read timeout for: " + it.url);
                                            break;
                                        }
                                    }

                                    String headerResp = headerBuf.toString(StandardCharsets.UTF_8.name());
                                    // Check for 200 status
                                    if (!headerResp.startsWith("HTTP/") || !(headerResp.contains(" 200 ") || headerResp.contains(" 200\r\n"))) {
                                        appendLog("Proxy CONNECT failed for " + it.url + " -> " + headerResp.replaceAll("\\r?\\n", " | "));
                                        results[idx] = makeErrorResult(it, "CONNECT failed: " + headerResp.split("\\r?\\n")[0]);
                                        failCount.incrementAndGet();
                                        continue;
                                    }

                                    // 3) Create SSLContext
                                    SSLContext sslContext = null;
                                    // try to load burp CA if provided
                                    if (configObj != null && configObj.burpCaPath != null && !configObj.burpCaPath.trim().isEmpty()) {
                                        try {
                                            File caFile = new File(configObj.burpCaPath);
                                            if (caFile.exists()) {
                                                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                                                FileInputStream fis = new FileInputStream(caFile);
                                                java.security.cert.Certificate caCert = cf.generateCertificate(fis);
                                                fis.close();

                                                KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
                                                ks.load(null, null);
                                                ks.setCertificateEntry("burp-ca", caCert);

                                                TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                                                tmf.init(ks);

                                                sslContext = SSLContext.getInstance("TLS");
                                                sslContext.init(null, tmf.getTrustManagers(), new java.security.SecureRandom());
                                            }
                                        } catch (Exception e) {
                                            appendLog("Failed to load burp CA from " + configObj.burpCaPath + ": " + e.getMessage());
                                            // fall through to trust-all if fails
                                        }
                                    }

                                    // fallback: trust-all (insecure) if no sslContext created
                                    if (sslContext == null) {
                                        try {
                                            TrustManager[] trustAll = new TrustManager[]{
                                                    new X509TrustManager() {
                                                        public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                                                            return new java.security.cert.X509Certificate[0];
                                                        }

                                                        public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) {
                                                        }

                                                        public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) {
                                                        }
                                                    }
                                            };
                                            sslContext = SSLContext.getInstance("TLS");
                                            sslContext.init(null, trustAll, new java.security.SecureRandom());
                                        } catch (Exception e) {
                                            appendLog("Failed to init trust-all SSLContext: " + e.getMessage());
                                            results[idx] = makeErrorResult(it, "SSL init error: " + e.getMessage());
                                            failCount.incrementAndGet();
                                            continue;
                                        }
                                    }

                                    // 4) wrap socket with SSLSocket
                                    SSLSocketFactory factory = sslContext.getSocketFactory();
                                    SSLSocket sslSocket = (SSLSocket) factory.createSocket(sock, targetHost, targetPort, true);
                                    sslSocket.setUseClientMode(true);
                                    // optional: enable host name verification? (we trust-all or burp CA)
                                    try {
                                        sslSocket.startHandshake();
                                    } catch (SSLHandshakeException she) {
                                        appendLog("SSL handshake failed for " + it.url + ": " + she.getMessage());
                                        results[idx] = makeErrorResult(it, "SSL handshake failed: " + she.getMessage());
                                        failCount.incrementAndGet();
                                        try {
                                            sslSocket.close();
                                        } catch (Exception ignored) {
                                        }
                                        continue;
                                    }

                                    // 5) send actual HTTP request over TLS (relative-form)
                                    // rebuild request bytes in relative form (path + query)
                                    byte[] tlsRequest = buildRequestBytes(it, headersMerged, false);
                                    OutputStream tlsOs = sslSocket.getOutputStream();
                                    InputStream tlsIs = sslSocket.getInputStream();
                                    tlsOs.write(tlsRequest);
                                    tlsOs.flush();

                                    // read response from tlsIs
                                    ByteArrayOutputStream bout = new ByteArrayOutputStream();
                                    byte[] buf = new byte[8192];
                                    int r;
                                    try {
                                        while ((r = tlsIs.read(buf)) != -1) {
                                            bout.write(buf, 0, r);
                                            if (bout.size() > 5 * 1024 * 1024) break;
                                        }
                                    } catch (SocketTimeoutException ste) {
                                        appendLog("TLS read timeout for: " + it.url);
                                    }

                                    byte[] respBytes = bout.toByteArray();
                                    int status = -1;
                                    String body = "";
                                    if (respBytes != null && respBytes.length > 0) {
                                        try {
                                            IResponseInfo ri = helpers.analyzeResponse(respBytes);
                                            status = ri.getStatusCode();
                                            int bodyOff = ri.getBodyOffset();
                                            body = new String(respBytes, bodyOff, respBytes.length - bodyOff, StandardCharsets.UTF_8);
                                        } catch (Exception ex) {
                                            body = new String(respBytes, StandardCharsets.UTF_8);
                                        }
                                    }

                                    Map<String, Object> rmap = new HashMap<>();
                                    rmap.put("url", it.url);
                                    rmap.put("method", it.method == null ? "GET" : it.method.toUpperCase());
                                    rmap.put("status", status);
                                    rmap.put("elapsed", 0);
                                    rmap.put("success", status >= 200 && status < 300);
                                    rmap.put("response", body.length() > 500 ? body.substring(0, 500) : body);
                                    results[idx] = rmap;
                                    if (status >= 200 && status < 300) successCount.incrementAndGet();
                                    else failCount.incrementAndGet();

                                    // close sslSocket (which will close underlying socket as well)
                                    try {
                                        sslSocket.close();
                                    } catch (Exception ignored) {
                                    }

                                } else {
                                    // HTTP target: write absolute-form request (already created earlier)
                                    os.write(requestBytes);
                                    os.flush();

                                    // read response bytes (simple read until stream closed or timeout)
                                    ByteArrayOutputStream bout = new ByteArrayOutputStream();
                                    byte[] buf = new byte[8192];
                                    int read;
                                    try {
                                        while ((read = is.read(buf)) != -1) {
                                            bout.write(buf, 0, read);
                                            if (bout.size() > 5 * 1024 * 1024) break;
                                        }
                                    } catch (SocketTimeoutException ste) {
                                        appendLog("Socket read timeout for: " + it.url);
                                    }

                                    byte[] respBytes = bout.toByteArray();
                                    int status = -1;
                                    String body = "";
                                    if (respBytes != null && respBytes.length > 0) {
                                        try {
                                            IResponseInfo ri = helpers.analyzeResponse(respBytes);
                                            status = ri.getStatusCode();
                                            int bodyOff = ri.getBodyOffset();
                                            body = new String(respBytes, bodyOff, respBytes.length - bodyOff, StandardCharsets.UTF_8);
                                        } catch (Exception ex) {
                                            body = new String(respBytes, StandardCharsets.UTF_8);
                                        }
                                    }

                                    Map<String, Object> rmap = new HashMap<>();
                                    rmap.put("url", it.url);
                                    rmap.put("method", it.method == null ? "GET" : it.method.toUpperCase());
                                    rmap.put("status", status);
                                    rmap.put("elapsed", 0);
                                    rmap.put("success", status >= 200 && status < 300);
                                    rmap.put("response", body.length() > 500 ? body.substring(0, 500) : body);
                                    results[idx] = rmap;
                                    if (status >= 200 && status < 300) successCount.incrementAndGet();
                                    else failCount.incrementAndGet();
                                }

                            } catch (IOException ioe) {
                                appendLog("Proxy socket error for: " + it.url + " -> " + ioe.getMessage());
                                results[idx] = makeErrorResult(it, ioe.getMessage());
                                failCount.incrementAndGet();
                            } finally {
                                if (sock != null) {
                                    try {
                                        sock.close();
                                    } catch (IOException ignored) {
                                    }
                                }
                            }
                        } else {
                            // Default: use callbacks.makeHttpRequest (Burp handles sending)
                            IHttpService service = buildService(it.url);
                            Callable<IHttpRequestResponse> call = () -> callbacks.makeHttpRequest(service, requestBytes);
                            Future<IHttpRequestResponse> future = executor.submit(call);
                            try {
                                long timeout = (it.timeoutMs != null) ? it.timeoutMs : globalTimeout;
                                IHttpRequestResponse resp = future.get(timeout, TimeUnit.MILLISECONDS);
                                if (resp != null) {
                                    byte[] respBytes = resp.getResponse();
                                    String body = "";
                                    int status = -1;
                                    if (respBytes != null) {
                                        IResponseInfo ri = helpers.analyzeResponse(respBytes);
                                        status = ri.getStatusCode();
                                        int bodyOff = ri.getBodyOffset();
                                        body = new String(respBytes, bodyOff, respBytes.length - bodyOff, StandardCharsets.UTF_8);
                                    }
                                    Map<String, Object> r = new HashMap<>();
                                    r.put("url", it.url);
                                    r.put("method", it.method == null ? "GET" : it.method.toUpperCase());
                                    r.put("status", status);
                                    r.put("elapsed", 0);
                                    r.put("success", status >= 200 && status < 300);
                                    r.put("response", body.length() > 500 ? body.substring(0, 500) : body);
                                    results[idx] = r;
                                    if (status >= 200 && status < 300) successCount.incrementAndGet();
                                    else failCount.incrementAndGet();
                                } else {
                                    results[idx] = makeErrorResult(it, "no response");
                                    failCount.incrementAndGet();
                                }
                            } catch (TimeoutException te) {
                                future.cancel(true);
                                appendLog("Timeout for url: " + it.url);
                                results[idx] = makeErrorResult(it, "timeout after " + ((it.timeoutMs != null) ? it.timeoutMs : globalTimeout) + " ms");
                                failCount.incrementAndGet();
                            } catch (Exception ex) {
                                future.cancel(true);
                                appendLog("Request failed for: " + it.url + " -> " + ex.getMessage());
                                results[idx] = makeErrorResult(it, ex.getMessage());
                                failCount.incrementAndGet();
                            }
                        }

                    } catch (Exception outerEx) {
                        appendLog("Worker unexpected error: " + outerEx.getMessage());
                        results[idx] = makeErrorResult(it, outerEx.getMessage());
                        failCount.incrementAndGet();
                    } finally {
                        inProgress.decrementAndGet();
                        updateProgressLabels();
                        latch.countDown();
                        // delay if configured in the interface
                        try {
                            if (it.delayMs != null && it.delayMs > 0) Thread.sleep(it.delayMs);
                        } catch (InterruptedException ignored) {
                        }
                    }
                } // end while
            }); // end submit worker
        } // end for workers

        // wait in background and save results when done
        executor.submit(() -> {
            try {
                latch.await();
            } catch (InterruptedException ignored) {
            }
            String fname = saveResults(results);
            appendLog("Run finished, results saved to " + fname);
        });
    }

    // buildRequestBytes with absoluteForm option
    private byte[] buildRequestBytes(InterfaceItem it, Map<String, String> headersMerged, boolean absoluteForm) throws Exception {
        URL u = new URL(it.url);
        String path = u.getPath().isEmpty() ? "/" : u.getPath();
        if (u.getQuery() != null && !u.getQuery().isEmpty()) {
            path += "?" + u.getQuery();
        }
        String method = (it.method == null ? "GET" : it.method.toUpperCase());
        StringBuilder sb = new StringBuilder();

        if (absoluteForm) {
            // full URL in request line
            sb.append(method).append(" ").append(it.url).append(" HTTP/1.1\r\n");
        } else {
            sb.append(method).append(" ").append(path).append(" HTTP/1.1\r\n");
        }

        // Host header should be actual target host
        sb.append("Host: ").append(u.getHost());
        if (u.getPort() != -1 && u.getPort() != u.getDefaultPort()) sb.append(":").append(u.getPort());
        sb.append("\r\n");

        // add merged headers (skip Host if present)
        if (headersMerged != null) {
            for (Map.Entry<String, String> e : headersMerged.entrySet()) {
                if ("Host".equalsIgnoreCase(e.getKey())) continue;
                sb.append(e.getKey()).append(": ").append(e.getValue()).append("\r\n");
            }
        }

        // body
        String bodyStr = "";
        boolean hasBody = it.body != null && !"GET".equalsIgnoreCase(method);
        if (hasBody) {
            if (headersMerged == null || !headersMerged.containsKey("Content-Type")) {
                sb.append("Content-Type: application/json\r\n");
            }
            Gson gson = new GsonBuilder().setPrettyPrinting().create();
            bodyStr = gson.toJson(it.body);
            byte[] bodyBytes = bodyStr.getBytes(StandardCharsets.UTF_8);
            sb.append("Content-Length: ").append(bodyBytes.length).append("\r\n");
        } else {
            sb.append("Content-Length: 0\r\n");
        }

        sb.append("\r\n");
        if (!bodyStr.isEmpty()) sb.append(bodyStr);

        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }


    // helper: build IHttpService from url
    private IHttpService buildService(String urlStr) {
        URL u;
        try {
            u = new URL(urlStr);
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
        String host = u.getHost();
        int port = u.getPort();
        String protocol = u.getProtocol(); // http or https
        if (port == -1) {
            if ("https".equalsIgnoreCase(protocol)) port = 443;
            else port = 80;
        }
        return helpers.buildHttpService(host, port, protocol);
    }

    private Map<String, Object> makeErrorResult(InterfaceItem it, String msg) {
        Map<String, Object> r = new HashMap<>();
        r.put("url", it.url);
        r.put("method", it.method == null ? "GET" : it.method.toUpperCase());
        r.put("error", msg);
        r.put("success", false);
        return r;
    }

    private String saveResults(Object[] results) {
        try {
            SimpleDateFormat fmt = new SimpleDateFormat("yyyyMMdd_HHmmss");
            String now = fmt.format(new Date());
            String fname = "result_" + now + ".json";
            File f = new File(resultsDir, fname);
            FileWriter fw = new FileWriter(f);
            Gson gson = new GsonBuilder().setPrettyPrinting().create();
            gson.toJson(results, fw);
            fw.close();
            return f.getAbsolutePath();
        } catch (Exception ex) {
            appendLog("Failed to save results: " + ex.getMessage());
            return null;
        }
    }

    private void updateProgressLabels() {
        SwingUtilities.invokeLater(() -> {
            lblTotal.setText("总数: " + total.get());
            lblInProgress.setText("进行中: " + inProgress.get());
            lblRemaining.setText("剩余: " + Math.max(0, total.get() - successCount.get() - failCount.get() - inProgress.get()));
            lblSuccess.setText("成功: " + successCount.get());
            lblFail.setText("失败: " + failCount.get());
        });
    }

    private void appendLog(String s) {
        callbacks.printOutput(s);
        SwingUtilities.invokeLater(() -> {
            logArea.append(s + "\n");
            logArea.setCaretPosition(logArea.getDocument().getLength());
        });
    }


    // ITab 接口实现
    @Override
    public String getTabCaption() {
        return "xia Yue执行请求";
    }

    @Override
    public Component getUiComponent() {
        return mainPanel;
    }

    static class Config {
        Boolean enabled;
        String burpCaPath;
        String burpProxyHost;
        Integer burpProxyPort;
        Map<String, String> headers;
        Long timeoutMs;
        Long delayMs;
        Integer concurrency;
        List<InterfaceItem> interfaces;
    }

    static class InterfaceItem {
        String name;
        String url;
        String method;
        Map<String, String> headers;
        Object body;
        Long timeoutMs;
        Long delayMs;
        Boolean enabled;
    }
}