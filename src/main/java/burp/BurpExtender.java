package burp;

import burp.utils.ResponseClassifier;
import burp.utils.ResponseClassifier.ResponseType;
import burp.utils.ResponseClassifier.YueType;
import burp.utils.Utils;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableModel;
import java.awt.*;
import java.io.PrintWriter;
import java.net.URL;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;

public class BurpExtender
        extends AbstractTableModel
        implements IBurpExtender, ITab, IHttpListener, IScannerCheck, IMessageEditorController {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private JSplitPane splitPane;
    private IMessageEditor requestViewer;
    private IMessageEditor responseViewer;
    private IMessageEditor requestViewer_1;
    private IMessageEditor responseViewer_1;
    private IMessageEditor requestViewer_2;
    private IMessageEditor responseViewer_2;
    private IMessageEditor requestViewer_3; // 低权限数据包2的改动, 显示请求体
    private IMessageEditor responseViewer_3; // 低权限数据包2的改动, 显示响应体
    private IHttpRequestResponse currentlyDisplayedItem;
    private final List<LogEntry> log = new ArrayList<>();
    private final List<Request_md5> log4_md5 = new ArrayList<>();
    private JTabbedPane tabs;
    public static PrintWriter stdout;
    int switchs = 0;
    int count = 0;
    int select_row = 0;
    Table logTable;
    String hostWhiteListStr = "";
    int white_switchs = 0;
    List<String> d1HeaderList = new ArrayList<>();
    List<String> d2HeaderList = new ArrayList<>(); // 低权限数据包2的改动, 配置区域
    List<String> unauthorizedHeaderList = new ArrayList<>();
    String otherConfig = "";
    String universal_cookie = "";
    String xy_version = "1.5_魔改版";
    private ResponseClassifier classifier;
    private JCheckBox conclusionCkb;
    private static HashSet<String> unauthorizedUrlWhiteSet = new HashSet<>();
    private static HashSet<String> lowUrlWhiteSet = new HashSet<>();


    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stdout.println("hello xia Yue!");
        stdout.println("你好 欢迎使用 瞎越!");
        stdout.println("version:" + this.xy_version);


        this.callbacks = callbacks;


        this.helpers = callbacks.getHelpers();
        this.classifier = new ResponseClassifier(callbacks);


        callbacks.setExtensionName("xia Yue V" + this.xy_version);


        SwingUtilities.invokeLater(new Runnable() {


            public void run() {
                BurpExtender.this.logTable = new BurpExtender.Table(BurpExtender.this);
                BurpExtender.this.logTable.getColumnModel().getColumn(0).setPreferredWidth(10);
                BurpExtender.this.logTable.getColumnModel().getColumn(1).setPreferredWidth(30); // 低权限数据包2的改动, 减少一下请求类型的长度
                BurpExtender.this.logTable.getColumnModel().getColumn(2).setPreferredWidth(300);
                DefaultTableCellRenderer cellRenderer = new DefaultTableCellRenderer() {
                    @Override
                    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
                        Component c = super.getTableCellRendererComponent(table, value,
                                isSelected, hasFocus, row, column);
                        if (value instanceof String) {
                            String strValue = (String) value;
                            if (strValue.contains("✘")) {
                                c.setForeground(Color.RED);
                            } else {
                                c.setForeground(Color.BLACK);
                            }
                        }
                        return c;
                    }
                };
                BurpExtender.this.logTable.getColumnModel().getColumn(4).setCellRenderer(cellRenderer);
                BurpExtender.this.logTable.getColumnModel().getColumn(5).setCellRenderer(cellRenderer);
                BurpExtender.this.logTable.getColumnModel().getColumn(6).setCellRenderer(cellRenderer);
                JScrollPane scrollPane = new JScrollPane(BurpExtender.this.logTable);


                JPanel jp = new JPanel();
                jp.setLayout(new GridLayout(1, 1));
                jp.add(scrollPane);


                JPanel jps = new JPanel();
                jps.setLayout(new GridLayout(5 + YueType.values().length, 1));
                List<JLabel> hintLabels = new ArrayList<>();
                for (YueType value : YueType.values()) {
                    hintLabels.add(new JLabel(value.getHint()));
                }
                final JCheckBox enableCkb = new JCheckBox("启动插件");
                conclusionCkb = new JCheckBox("自动结论", true);
                final JCheckBox chkbox2 = new JCheckBox("启动万能cookie");
                JLabel hostWhiteListLabel = new JLabel("如果需要多个域名加白请用,隔开");
                final JTextField hostWhiteListTextField = new JTextField("填写白名单域名");

                JButton clearListBtn = new JButton("清空列表");
                final JButton enableHostWhiteListBtn = new JButton("启动白名单");

                JLabel d1HeaderLabel = new JLabel("越权:替换<低权限数据包>的header");
                final JTextArea d1HeaderTextArea = new JTextArea("Cookie: JSESSIONID=test;UUID=1; userid=admin\nAuthorization: Bearer test", 5, 30);
                JScrollPane d1HeaderScrollPane = new JScrollPane(d1HeaderTextArea);

                // 低权限数据包2的改动, 配置区
                JLabel d2HeaderLabel = new JLabel("越权:替换<低权限数据包2>的header");
                final JTextArea d2HeaderTextArea = new JTextArea("Cookie: JSESSIONID=test;UUID=2; userid=normal\nAuthorization: Bearer test", 5, 30);
                JScrollPane d2HeaderScrollPane = new JScrollPane(d2HeaderTextArea);

                JLabel unauthorizedHeaderLabel = new JLabel("未授权:移除<未授权数据包>的header");
                final JTextArea unauthorizedHeaderTextArea = new JTextArea("Cookie\nAuthorization\nToken", 5, 30);
                JScrollPane unauthorizedHeaderScrollPane = new JScrollPane(unauthorizedHeaderTextArea);

                JLabel otherConfigLabel = new JLabel("其他配置");
                final JTextArea otherConfigTextArea = new JTextArea("{\n}", 5, 30);
                JScrollPane otherConfigScrollPane = new JScrollPane(otherConfigTextArea);

                JLabel lowUrlWhiteListLabel = new JLabel("不算越权的url白名单(正则)<低权限数据包,低权限数据包2>");
                final JTextArea lowUrlWhiteListTextArea = new JTextArea("", 5, 30);
                JScrollPane lowUrlWhiteListScrollPane = new JScrollPane(lowUrlWhiteListTextArea);

                JLabel unauthorizedUrlWhiteListLabel = new JLabel("不算越权的url白名单(正则)<未授权数据包>");
                final JTextArea unauthorizedUrlWhiteListTextArea = new JTextArea("", 5, 30);
                JScrollPane unauthorizedUrlWhiteListScrollPane = new JScrollPane(unauthorizedUrlWhiteListTextArea);

                JTabbedPane configTabs = new JTabbedPane();
                JPanel headerPanel = new JPanel();
                headerPanel.add(d1HeaderLabel);
                headerPanel.add(d1HeaderScrollPane);
                headerPanel.add(d2HeaderLabel);
                headerPanel.add(d2HeaderScrollPane);
                headerPanel.add(unauthorizedHeaderLabel);
                headerPanel.add(unauthorizedHeaderScrollPane);
//                headerPanel.add(otherConfigLabel);
//                headerPanel.add(otherConfigScrollPane);
                headerPanel.setLayout(new GridLayout(6, 1, 0, 0)); // 低权限数据包2的改动, 5增加到7

                JPanel respPanel = new JPanel();
                JLabel authFailLabel = new JLabel("响应包含以下关键字,判定成鉴权失败的请求");
                final JTextArea authFailTextArea = new JTextArea("", 5, 30);
                JScrollPane authFailScrollPane = new JScrollPane(authFailTextArea);
                respPanel.add(authFailLabel);
                respPanel.add(authFailScrollPane);
                respPanel.add(lowUrlWhiteListLabel);
                respPanel.add(lowUrlWhiteListScrollPane);
                respPanel.add(unauthorizedUrlWhiteListLabel);
                respPanel.add(unauthorizedUrlWhiteListScrollPane);
                respPanel.setLayout(new GridLayout(6, 1, 0, 0));

                configTabs.addTab("替换header", headerPanel);
                configTabs.addTab("自动判断越权", respPanel);

                enableCkb.addItemListener(e -> {
                    if (enableCkb.isSelected()) {
                        String d1HeaderStr = defaultIfBlank(d1HeaderTextArea.getText(), "");
                        BurpExtender.this.d1HeaderList = Arrays.asList(d1HeaderStr.split("\n"));
                        String d2HeaderStr = defaultIfBlank(d2HeaderTextArea.getText(), "");
                        BurpExtender.this.d2HeaderList = Arrays.asList(d2HeaderStr.split("\n"));
                        String unauthorizedHeaderStr = defaultIfBlank(unauthorizedHeaderTextArea.getText(), "");
                        BurpExtender.this.unauthorizedHeaderList = Arrays.asList(unauthorizedHeaderStr.split("\n"));
                        BurpExtender.this.otherConfig = otherConfigTextArea.getText();
                        String unauthorizedUrlText = defaultIfBlank(unauthorizedUrlWhiteListTextArea.getText(), "");
                        BurpExtender.unauthorizedUrlWhiteSet = new HashSet<>(Arrays.asList(unauthorizedUrlText.split("\n")));
                        String lowUrlText = defaultIfBlank(lowUrlWhiteListTextArea.getText(), "");
                        BurpExtender.lowUrlWhiteSet = new HashSet<>(Arrays.asList(lowUrlText.split("\n")));
                        String authFailText = defaultIfBlank(authFailTextArea.getText(), "");
                        BurpExtender.this.classifier.setAuthFailKeywords(new HashSet<>(Arrays.asList(authFailText.split("\n"))));

                        BurpExtender.this.switchs = 1;
                        disableTextArea(d1HeaderTextArea);
                        disableTextArea(d2HeaderTextArea);
                        disableTextArea(unauthorizedHeaderTextArea);
                        disableTextArea(otherConfigTextArea);
                        disableTextArea(lowUrlWhiteListTextArea);
                        disableTextArea(unauthorizedUrlWhiteListTextArea);
                        disableTextArea(authFailTextArea);
                    } else {
                        BurpExtender.this.switchs = 0;
                        enableTextArea(d1HeaderTextArea);
                        enableTextArea(d2HeaderTextArea);
                        enableTextArea(unauthorizedHeaderTextArea);
                        enableTextArea(otherConfigTextArea);
                        enableTextArea(lowUrlWhiteListTextArea);
                        enableTextArea(unauthorizedUrlWhiteListTextArea);
                        enableTextArea(authFailTextArea);
                    }
                });

                chkbox2.addItemListener(e -> {
                    if (chkbox2.isSelected()) {
                        BurpExtender.this.universal_cookie = "";
                    } else {
                        BurpExtender.this.universal_cookie = "";
                    }
                });

                clearListBtn.addActionListener(e -> {
                    BurpExtender.this.log.clear();
                    BurpExtender.this.count = 0;
                    BurpExtender.this.log4_md5.clear();
                    BurpExtender.this.fireTableRowsInserted(BurpExtender.this.log.size(), BurpExtender.this.log.size());
                });
                enableHostWhiteListBtn.addActionListener(e -> {
                    if (enableHostWhiteListBtn.getText().equals("启动白名单")) {
                        enableHostWhiteListBtn.setText("关闭白名单");
                        BurpExtender.this.hostWhiteListStr = hostWhiteListTextField.getText();
                        BurpExtender.this.white_switchs = 1;
                        hostWhiteListTextField.setEditable(false);
                        hostWhiteListTextField.setForeground(Color.GRAY);
                    } else {
                        enableHostWhiteListBtn.setText("启动白名单");
                        BurpExtender.this.white_switchs = 0;
                        hostWhiteListTextField.setEditable(true);
                        hostWhiteListTextField.setForeground(Color.BLACK);
                    }
                });

                for (JLabel hintLabel : hintLabels) {
                    jps.add(hintLabel);
                }
                JPanel checkboxPanel = new JPanel();
                checkboxPanel.setLayout(new BoxLayout(checkboxPanel, BoxLayout.X_AXIS)); // 横向排列
                checkboxPanel.add(enableCkb);
                checkboxPanel.add(conclusionCkb);
                jps.add(checkboxPanel);

                jps.add(clearListBtn);
                jps.add(hostWhiteListLabel);
                jps.add(hostWhiteListTextField);
                jps.add(enableHostWhiteListBtn);

                BurpExtender.this.tabs = new JTabbedPane();
                BurpExtender.this.requestViewer = callbacks.createMessageEditor(BurpExtender.this, false);
                BurpExtender.this.responseViewer = callbacks.createMessageEditor(BurpExtender.this, false);
                BurpExtender.this.requestViewer_1 = callbacks.createMessageEditor(BurpExtender.this, false);
                BurpExtender.this.responseViewer_1 = callbacks.createMessageEditor(BurpExtender.this, false);
                BurpExtender.this.requestViewer_2 = callbacks.createMessageEditor(BurpExtender.this, false);
                BurpExtender.this.responseViewer_2 = callbacks.createMessageEditor(BurpExtender.this, false);
                // 低权限数据包2的改动, 请求,响应区域
                BurpExtender.this.requestViewer_3 = callbacks.createMessageEditor(BurpExtender.this, false);
                BurpExtender.this.responseViewer_3 = callbacks.createMessageEditor(BurpExtender.this, false);

                JSplitPane originSplitPanel = new JSplitPane(1);
                originSplitPanel.setDividerLocation(500);
                originSplitPanel.setLeftComponent(BurpExtender.this.requestViewer.getComponent());
                originSplitPanel.setRightComponent(BurpExtender.this.responseViewer.getComponent());

                JSplitPane d1SplitPanel = new JSplitPane(1);
                d1SplitPanel.setDividerLocation(500);
                d1SplitPanel.setLeftComponent(BurpExtender.this.requestViewer_1.getComponent());
                d1SplitPanel.setRightComponent(BurpExtender.this.responseViewer_1.getComponent());

                JSplitPane unauthorizedSplitPanel = new JSplitPane(1);
                unauthorizedSplitPanel.setDividerLocation(500);
                unauthorizedSplitPanel.setLeftComponent(BurpExtender.this.requestViewer_2.getComponent());
                unauthorizedSplitPanel.setRightComponent(BurpExtender.this.responseViewer_2.getComponent());

                JSplitPane d2SplitPanel = new JSplitPane(1);
                d2SplitPanel.setDividerLocation(500);
                d2SplitPanel.setLeftComponent(BurpExtender.this.requestViewer_3.getComponent());
                d2SplitPanel.setRightComponent(BurpExtender.this.responseViewer_3.getComponent());

                BurpExtender.this.tabs.addTab("原始数据包", originSplitPanel);
                BurpExtender.this.tabs.addTab("低权限数据包", d1SplitPanel);
                BurpExtender.this.tabs.addTab("未授权数据包", unauthorizedSplitPanel);
                BurpExtender.this.tabs.addTab("低权限数据包2", d2SplitPanel);

                JSplitPane leftSplitPanes = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
                leftSplitPanes.setTopComponent(jp);
                leftSplitPanes.setBottomComponent(BurpExtender.this.tabs);

                JSplitPane rightSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
                rightSplitPane.setTopComponent(jps);
                rightSplitPane.setBottomComponent(configTabs);

                BurpExtender.this.splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
                BurpExtender.this.splitPane.setLeftComponent(leftSplitPanes);
                BurpExtender.this.splitPane.setRightComponent(rightSplitPane);
                BurpExtender.this.splitPane.setDividerLocation(1000);

                callbacks.customizeUiComponent(BurpExtender.this.splitPane);
                callbacks.customizeUiComponent(BurpExtender.this.logTable);
                callbacks.customizeUiComponent(scrollPane);
                callbacks.customizeUiComponent(jps);
                callbacks.customizeUiComponent(jp);
                callbacks.customizeUiComponent(BurpExtender.this.tabs);
                callbacks.addSuiteTab(BurpExtender.this);

                HttpExecutorTab httpExecutorTab = new HttpExecutorTab(callbacks, helpers);
                httpExecutorTab.buildUi();
                callbacks.addSuiteTab(httpExecutorTab);

                callbacks.registerHttpListener(BurpExtender.this);
                callbacks.registerScannerCheck(BurpExtender.this);
            }

            private String defaultIfBlank(String text, String defaultValue) {
                if (text != null && !text.isEmpty()) {
                    text = text.trim();
                } else {
                    text = defaultValue;
                }
                return text;
            }
        });
    }

    private void disableTextArea(JTextArea textArea) {
        textArea.setForeground(Color.BLACK);
        textArea.setBackground(Color.LIGHT_GRAY);
        textArea.setEditable(false);
    }

    private void enableTextArea(JTextArea textArea) {
        textArea.setForeground(Color.BLACK);
        textArea.setBackground(Color.WHITE);
        textArea.setEditable(true);
    }

    public String getTabCaption() {
        return "xia Yue魔改版";
    }


    public Component getUiComponent() {
        return this.splitPane;
    }

    public void processHttpMessage(final int toolFlag, boolean messageIsRequest, final IHttpRequestResponse messageInfo) {
        if (this.switchs == 1 &&
                toolFlag == 4) {
            if (!messageIsRequest) {
                synchronized (this.log) {
                    Thread thread = new Thread(() -> {
                        try {
                            BurpExtender.this.checkVul(messageInfo, toolFlag);
                        } catch (Exception ex) {
                            BurpExtender.stdout.println("发生异常:" + Utils.getStackTrace(ex));
                        }
                    });
                    thread.start();
                }
            }
        }
    }


    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        return null;
    }

    private void checkVul(IHttpRequestResponse baseRequestResponse, int toolFlag) {
        String url = String.valueOf(this.helpers.analyzeRequest(baseRequestResponse).getUrl());
        int original_data_len = (baseRequestResponse.getResponse()).length;
        int original_len = original_data_len - this.helpers.analyzeResponse(baseRequestResponse.getResponse()).getBodyOffset();
        String requestUrl = url.split("\\?")[0];

        String[] whiteUrlList = this.hostWhiteListStr.split(",");
        int white_swith;
        if (this.white_switchs == 1) {
            white_swith = 0;
            for (String whiteUrl : whiteUrlList) {
                if (requestUrl.contains(whiteUrl)) {
                    //stdout.println("白名单域名的URL！" + requestUrl);
                    white_swith = 1;
                }
            }
            if (white_swith == 0) {
                //stdout.println("不是白名单域名的URL！" + requestUrl);
                return;
            }
        }

        if (toolFlag == 4 || toolFlag == 64) {
            String[] static_file = {"jpg", "png", "gif", "css", "js", "pdf", "mp3", "mp4", "avi", "map", "svg", "ico", "svg", "woff", "woff2", "ttf"};
            String[] static_file_1 = requestUrl.split("\\.");
            String static_file_2 = static_file_1[static_file_1.length - 1];
            for (String str : static_file) {
                if (static_file_2.equals(str)) {
                    //stdout.println("当前url为静态文件：" + requestUrl + "\n");
                    return;
                }
            }
        }

        List<IParameter> paraLists = this.helpers.analyzeRequest(baseRequestResponse).getParameters();
        for (IParameter para : paraLists) {
            requestUrl = requestUrl + "+" + para.getName();
        }


        requestUrl = requestUrl + "+" + this.helpers.analyzeRequest(baseRequestResponse).getMethod();
        requestUrl = LogEntry.MD5(requestUrl);
//        stdout.println("\nMD5(\"" + requestUrl + "\") = " + requestUrl);

        for (Request_md5 request_md5 : this.log4_md5) {
            if (request_md5.md5_data.equals(requestUrl)) {
                return;
            }
        }
        this.log4_md5.add(new Request_md5(requestUrl));


        IRequestInfo requestInfo = this.helpers.analyzeRequest(baseRequestResponse);
        IHttpService iHttpService = baseRequestResponse.getHttpService();
        String request = this.helpers.bytesToString(baseRequestResponse.getRequest());
        int bodyOffset = requestInfo.getBodyOffset();
        byte[] body = request.substring(bodyOffset).getBytes();


        List<String> d1Headers = requestInfo.getHeaders();
        for (int i = 0; i < d1Headers.size(); i++) {
            String headKey = d1Headers.get(i).split(":")[0];
            for (String d1ConfigHeader : d1HeaderList) {
                if (headKey.equals(d1ConfigHeader.split(":")[0])) {
                    d1Headers.remove(i);
                    i--;
                }
            }
        }
        for (String d1ConfigHeader : d1HeaderList) {
            d1Headers.add(d1Headers.size() / 2, d1ConfigHeader);
        }


        byte[] d1Request = this.helpers.buildHttpMessage(d1Headers, body);
        IHttpRequestResponse d1Response = this.callbacks.makeHttpRequest(iHttpService, d1Request);
        int d1Len = (d1Response.getResponse()).length - this.helpers.analyzeResponse(d1Response.getResponse()).getBodyOffset();
        String d1LenDisplay;
        if (original_len == 0) {
            d1LenDisplay = Integer.toString(d1Len);
        } else if (original_len == d1Len) {
            d1LenDisplay = d1Len + "  ✔";
        } else {
            d1LenDisplay = d1Len + "  ==> " + (original_len - d1Len);
        }

        // 低权限数据包2的改动, 修改头,发送请求
        List<String> d2Headers = requestInfo.getHeaders();
        for (int k = 0; k < d2Headers.size(); k++) {
            String headKey = d2Headers.get(k).split(":")[0];
            for (String d2ConfigHeader : d2HeaderList) {
                if (headKey.equals(d2ConfigHeader.split(":")[0])) {
                    d2Headers.remove(k);
                    k--;
                }
            }
        }
        for (String d2ConfigHeader : d2HeaderList) {
            d2Headers.add(d2Headers.size() / 2, d2ConfigHeader);
        }

        byte[] d2Request = this.helpers.buildHttpMessage(d2Headers, body);
        IHttpRequestResponse d2Response = this.callbacks.makeHttpRequest(iHttpService, d2Request);
        int d2Len = (d2Response.getResponse()).length - this.helpers.analyzeResponse(d2Response.getResponse()).getBodyOffset();
        String d2LenDisplay;
        if (original_len == 0) {
            d2LenDisplay = Integer.toString(d2Len);
        } else if (original_len == d2Len) {
            d2LenDisplay = d2Len + "  ✔";
        } else {
            d2LenDisplay = d2Len + "  ==> " + (original_len - d2Len);
        }


        List<String> unauthorizedHeaders = requestInfo.getHeaders();
        for (int j = 0; j < unauthorizedHeaders.size(); j++) {
            String head_key = unauthorizedHeaders.get(j).split(":")[0];
            for (String unauthorizedConfigHeader : this.unauthorizedHeaderList) {
                if (head_key.equals(unauthorizedConfigHeader)) {
                    unauthorizedHeaders.remove(j);
                    j--;
                }
            }
        }
        if (!this.universal_cookie.isEmpty()) {
            String[] universal_cookies = this.universal_cookie.split("\n");
            unauthorizedHeaders.add(unauthorizedHeaders.size() / 2, universal_cookies[0]);
            unauthorizedHeaders.add(unauthorizedHeaders.size() / 2, universal_cookies[1]);
        }

        byte[] unauthorizedRequest = this.helpers.buildHttpMessage(unauthorizedHeaders, body);
        IHttpRequestResponse unauthorizedResponse = this.callbacks.makeHttpRequest(iHttpService, unauthorizedRequest);
        int unauthorizedLen = (unauthorizedResponse.getResponse()).length - this.helpers.analyzeResponse(unauthorizedResponse.getResponse()).getBodyOffset();
        String unauthorizedLenDisplay;
        if (original_len == 0) {
            unauthorizedLenDisplay = Integer.toString(unauthorizedLen);
        } else if (original_len == unauthorizedLen) {
            unauthorizedLenDisplay = unauthorizedLen + "  ✔";
        } else {
            unauthorizedLenDisplay = unauthorizedLen + "  ==> " + (original_len - unauthorizedLen);
        }

        int id = ++this.count;
        // 低权限数据包2的改动, 调整了LogEntry构造方法

        IHttpRequestResponsePersisted originPersisted = this.callbacks.saveBuffersToTempFiles(baseRequestResponse);
        IHttpRequestResponsePersisted d1Persisted = this.callbacks.saveBuffersToTempFiles(d1Response);
        IHttpRequestResponsePersisted d2Persisted = this.callbacks.saveBuffersToTempFiles(d2Response);
        IHttpRequestResponsePersisted unauthorizedPersisted = this.callbacks.saveBuffersToTempFiles(unauthorizedResponse);
        ResponseType originResponseType = classifier.classifyResponse(originPersisted);
        ResponseType d1ResponseType = classifier.classifyResponse(d1Persisted);
        ResponseType d2ResponseType = classifier.classifyResponse(d2Persisted);
        ResponseType unauthorizedResponseType = classifier.classifyResponse(unauthorizedPersisted);

        this.log.add(new LogEntry(id, requestInfo.getMethod(), requestInfo.getUrl(),
                originPersisted, d1Persisted, d2Persisted, unauthorizedPersisted,
                original_len, d1Len, d2Len, unauthorizedLen,
                d1LenDisplay, d2LenDisplay, unauthorizedLenDisplay,
                originResponseType, d1ResponseType, d2ResponseType, unauthorizedResponseType
        ));

        fireTableDataChanged();

        this.logTable.setRowSelectionInterval(this.select_row, this.select_row);
    }


    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return null;
    }


    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        if (existingIssue.getIssueName().equals(newIssue.getIssueName()))
            return -1;
        return 0;
    }


    public int getRowCount() {
        return this.log.size();
    }


    // 低权限数据包2的改动, 表格增加了一列, 6改成7
    public int getColumnCount() {
        return 7;
    }


    public String getColumnName(int columnIndex) {
        switch (columnIndex) {

            case 0:
                return "#";
            case 1:
                return "类型";
            case 2:
                return "URL";
            case 3:
                return "原始包长度";
            case 4:
                return "低权限包长度";
            case 5:
                return "未授权包长度";
            case 6: // 低权限数据包2的改动, 表格增加了一列, 6改成7
                return "低权限包长度2";
        }
        return "";
    }


    public Class<?> getColumnClass(int columnIndex) {
        return String.class;
    }


    public Object getValueAt(int rowIndex, int columnIndex) {
        LogEntry logEntry = this.log.get(rowIndex);

        switch (columnIndex) {
            case 0:
                return logEntry.id;
            case 1:
                return logEntry.Method;
            case 2:
                return logEntry.url;
            case 3:
                return logEntry.originalLen;
            case 4:
                if (conclusionCkb.isSelected()) {
                    return logEntry.d1YueResult;
                } else {
                    return logEntry.d1LenDisplay;
                }
            case 5:
                if (conclusionCkb.isSelected()) {
                    return logEntry.unauthorizedYueResult;
                } else {
                    return logEntry.unauthorizedLenDisplay;
                }
            case 6: // 低权限数据包2的改动, 表格增加了一列, 6改成7
                if (conclusionCkb.isSelected()) {
                    return logEntry.d2YueResult;
                } else {
                    return logEntry.d2LenDisplay;
                }
        }
        return "";
    }


    public byte[] getRequest() {
        return this.currentlyDisplayedItem.getRequest();
    }


    public byte[] getResponse() {
        return this.currentlyDisplayedItem.getResponse();
    }


    public IHttpService getHttpService() {
        return this.currentlyDisplayedItem.getHttpService();
    }


    private class Table
            extends JTable {
        public Table(TableModel tableModel) {
            super(tableModel);
        }


        public void changeSelection(int row, int col, boolean toggle, boolean extend) {
            BurpExtender.LogEntry logEntry = BurpExtender.this.log.get(row);
            BurpExtender.this.select_row = row;


            if (col == 4) {
                BurpExtender.this.tabs.setSelectedIndex(1);
            } else if (col == 5) {
                BurpExtender.this.tabs.setSelectedIndex(2);
            } else if (col == 3) {
                BurpExtender.this.tabs.setSelectedIndex(0);
            }

            BurpExtender.this.requestViewer.setMessage(logEntry.originPersisted.getRequest(), true);
            BurpExtender.this.responseViewer.setMessage(logEntry.originPersisted.getResponse(), false);
            BurpExtender.this.currentlyDisplayedItem = logEntry.originPersisted;
            BurpExtender.this.requestViewer_1.setMessage(logEntry.d1Persisted.getRequest(), true);
            BurpExtender.this.responseViewer_1.setMessage(logEntry.d1Persisted.getResponse(), false);
//            BurpExtender.this.currentlyDisplayedItem_1 = logEntry.d1Persisted;
            BurpExtender.this.requestViewer_2.setMessage(logEntry.unauthorizedPersisted.getRequest(), true);
            BurpExtender.this.responseViewer_2.setMessage(logEntry.unauthorizedPersisted.getResponse(), false);
//            BurpExtender.this.currentlyDisplayedItem_2 = logEntry.unauthorizedPersisted;
            // 低权限数据包2的改动,
            BurpExtender.this.requestViewer_3.setMessage(logEntry.d2Persisted.getRequest(), true);
            BurpExtender.this.responseViewer_3.setMessage(logEntry.d2Persisted.getResponse(), false);
//            BurpExtender.this.currentlyDisplayedItem_3 = logEntry.d2Persisted;

            super.changeSelection(row, col, toggle, extend);
        }
    }


    private static class Request_md5 {
        final String md5_data;


        Request_md5(String md5_data) {
            this.md5_data = md5_data;
        }
    }


    private static class LogEntry {
        final int id;

        final String Method;

        final IHttpRequestResponsePersisted originPersisted;
        final IHttpRequestResponsePersisted d1Persisted;
        final IHttpRequestResponsePersisted unauthorizedPersisted;
        final IHttpRequestResponsePersisted d2Persisted; // 低权限数据包2的改动,
        final String url;
        final String path;
        final int originalLen;
        final int d1Len;
        final int unauthorizedLen;
        final int d2Len;
        final String d1LenDisplay;
        final String unauthorizedLenDisplay;
        final String d2LenDisplay; // 低权限数据包2的改动,
        final ResponseType originResponseType;
        final ResponseType d1ResponseType;
        final ResponseType unauthorizedResponseType;
        final ResponseType d2ResponseType;
        String d1YueResult;
        String unauthorizedYueResult;
        String d2YueResult;

        // 低权限数据包2的改动, 调整了构造方法入参
        LogEntry(int id, String Method, URL url,
                 IHttpRequestResponsePersisted originPersisted,
                 IHttpRequestResponsePersisted d1Persisted,
                 IHttpRequestResponsePersisted d2Persisted,
                 IHttpRequestResponsePersisted unauthorizedPersisted,
                 int originalLen, int d1Len, int d2Len, int unauthorizedLen,
                 String d1LenDisplay, String d2LenDisplay, String unauthorizedLenDisplay,
                 ResponseType originResponseType,
                 ResponseType d1ResponseType,
                 ResponseType d2ResponseType,
                 ResponseType unauthorizedResponseType) {
            this.id = id;
            this.Method = Method;
            this.url = String.valueOf(url);
            this.path = url.getPath();
            this.originPersisted = originPersisted;
            this.d1Persisted = d1Persisted;
            this.d2Persisted = d2Persisted; // 低权限数据包2的改动,
            this.unauthorizedPersisted = unauthorizedPersisted;
            this.originalLen = originalLen;
            this.d1Len = d1Len;
            this.d2Len = d2Len;
            this.unauthorizedLen = unauthorizedLen;
            this.d1LenDisplay = d1LenDisplay;
            this.d2LenDisplay = d2LenDisplay; // 低权限数据包2的改动,
            this.unauthorizedLenDisplay = unauthorizedLenDisplay;
            this.originResponseType = originResponseType;
            this.d1ResponseType = d1ResponseType;
            this.d2ResponseType = d2ResponseType;
            this.unauthorizedResponseType = unauthorizedResponseType;

            this.calculateYueResult();
        }

        public void calculateYueResult() {
            if ("OPTIONS".equals(this.Method)) {
                this.d1YueResult = "忽略";
                this.unauthorizedYueResult = "忽略";
                this.d2YueResult = "忽略";
                return;
            }
            if (originResponseType != ResponseType.SUCCESS) {
                this.d1YueResult = "先确保原始数据包成功";
                this.unauthorizedYueResult = "先确保原始数据包成功";
                this.d2YueResult = "先确保原始数据包成功";
                return;
            }
            this.d1YueResult = calD1YueResult().getCode();
            this.unauthorizedYueResult = calUnauthorizedYueResult().getCode();
            this.d2YueResult = calD2YueResult().getCode();
        }

        private YueType calD1YueResult() {
            YueType result;
            if (this.d1ResponseType == ResponseType.SUCCESS) {
                if (this.d1Len == this.originalLen) {
                    if (isInLowWhiteList(this.path)) {
                        result = YueType.NO_IN_WHITE_LIST;
                    } else {
                        result = YueType.YES_SAME_SAME_NOT_IN_WHITE_LIST;
                    }
                } else {
                    result = YueType.NO_SIZE_NOT_SAME;
                }
            } else if (this.d1ResponseType == ResponseType.AUTH_FAILURE) {
                result = YueType.NO_AUTHENTICATION;
            } else if (this.d1ResponseType == ResponseType.API_ERROR) {
                result = YueType.YES_API_ERROR;
            } else {
                result = YueType.YES_IMPOSSIBLE;
            }
            return result;
        }

        private YueType calD2YueResult() {
            YueType result;
            if (this.d2ResponseType == ResponseType.SUCCESS) {
                if (this.d2Len == this.originalLen) {
                    if (isInLowWhiteList(this.path)) {
                        result = YueType.NO_IN_WHITE_LIST;
                    } else {
                        result = YueType.YES_SAME_SAME_NOT_IN_WHITE_LIST;
                    }
                } else {
                    result = YueType.NO_SIZE_NOT_SAME;
                }
            } else if (this.d2ResponseType == ResponseType.AUTH_FAILURE) {
                result = YueType.NO_AUTHENTICATION;
            } else if (this.d2ResponseType == ResponseType.API_ERROR) {
                result = YueType.YES_API_ERROR;
            } else {
                result = YueType.YES_IMPOSSIBLE;
            }
            return result;
        }

        private YueType calUnauthorizedYueResult() {
            YueType result;
            if (this.unauthorizedResponseType == ResponseType.SUCCESS) {
                if (isInUnauthorizedWhiteList(this.path)) {
                    result = YueType.NO_IN_WHITE_LIST;
                } else {
                    result = YueType.YES_NOT_SUCCESS_IF_NO_LOGIN;
                }
            } else if (this.unauthorizedResponseType == ResponseType.AUTH_FAILURE) {
                result = YueType.NO_AUTHENTICATION;
            } else if (this.unauthorizedResponseType == ResponseType.API_ERROR) {
                result = YueType.YES_API_ERROR;
            } else {
                result = YueType.YES_IMPOSSIBLE;
            }
            return result;
        }

        private boolean isInLowWhiteList(String path) {
            boolean fullMatch = lowUrlWhiteSet.contains(path);
            if (fullMatch) {
                return true;
            } else {
                for (String pattern : lowUrlWhiteSet) {
                    if (path.matches(pattern)) {
                        return true;
                    }
                }
            }
            return false;
        }

        private boolean isInUnauthorizedWhiteList(String path) {
            boolean fullMatch = unauthorizedUrlWhiteSet.contains(path);
            if (fullMatch) {
                return true;
            } else {
                for (String pattern : unauthorizedUrlWhiteSet) {
                    if (path.matches(pattern)) {
                        return true;
                    }
                }
            }
            return false;
        }


        public static String MD5(String key) {
            char[] hexDigits = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};


            try {
                byte[] btInput = key.getBytes();

                MessageDigest mdInst = MessageDigest.getInstance("MD5");

                mdInst.update(btInput);

                byte[] md = mdInst.digest();

                int j = md.length;
                char[] str = new char[j * 2];
                int k = 0;
                for (int i = 0; i < j; i++) {
                    byte byte0 = md[i];
                    str[k++] = hexDigits[byte0 >>> 4 & 0xF];
                    str[k++] = hexDigits[byte0 & 0xF];
                }
                return new String(str);
            } catch (Exception e) {
                return null;
            }
        }
    }
}
