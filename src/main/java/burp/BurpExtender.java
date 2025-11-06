 package burp;
 
 import java.awt.Color;
 import java.awt.Component;
 import java.awt.GridLayout;
 import java.awt.event.ActionEvent;
 import java.awt.event.ActionListener;
 import java.awt.event.ItemEvent;
 import java.awt.event.ItemListener;
 import java.io.PrintWriter;
 import java.security.MessageDigest;
 import java.util.ArrayList;
 import java.util.List;
 import javax.swing.JButton;
 import javax.swing.JCheckBox;
 import javax.swing.JLabel;
 import javax.swing.JPanel;
 import javax.swing.JScrollPane;
 import javax.swing.JSplitPane;
 import javax.swing.JTabbedPane;
 import javax.swing.JTable;
 import javax.swing.JTextArea;
 import javax.swing.JTextField;
 import javax.swing.SwingUtilities;
 import javax.swing.table.AbstractTableModel;
 import javax.swing.table.TableModel;
 
 
 
 
 public class BurpExtender
   extends AbstractTableModel
   implements IBurpExtender, ITab, IHttpListener, IScannerCheck, IMessageEditorController
 {
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
   private final List<LogEntry> log = new ArrayList<>();
   private IHttpRequestResponse currentlyDisplayedItem;
   private IHttpRequestResponse currentlyDisplayedItem_1;
   private IHttpRequestResponse currentlyDisplayedItem_2;
            private IHttpRequestResponse currentlyDisplayedItem_3; // 低权限数据包2的改动, 其实没啥用
   private final List<Request_md5> log4_md5 = new ArrayList<>();
   public PrintWriter stdout;
   JTabbedPane tabs;
   int switchs = 0;
   int conut = 0;
   int original_data_len;
   String temp_data;
   int select_row = 0;
   Table logTable;
   String white_URL = "";
   int white_switchs = 0;
   String data_1 = "";
   String data_2 = "";
            String data_d2 = ""; // 低权限数据包2的改动, 配置区域
   String universal_cookie = "";
   String xy_version = "1.4_魔改版";
 
 
 
   
   public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
     this.stdout = new PrintWriter(callbacks.getStdout(), true);
     this.stdout.println("hello xia Yue!");
     this.stdout.println("你好 欢迎使用 瞎越!");
     this.stdout.println("version:" + this.xy_version);
 
 
 
     
     this.callbacks = callbacks;
 
     
     this.helpers = callbacks.getHelpers();
 
     
     callbacks.setExtensionName("xia Yue V" + this.xy_version);
 
     
     SwingUtilities.invokeLater(new Runnable()
         {
 
 
           
           public void run()
           {
             BurpExtender.this.splitPane = new JSplitPane(1);
             JSplitPane splitPanes = new JSplitPane(0);
             JSplitPane splitPanes_2 = new JSplitPane(0);
 
             
             BurpExtender.this.logTable = new BurpExtender.Table(BurpExtender.this);
             BurpExtender.this.logTable.getColumnModel().getColumn(0).setPreferredWidth(10);
             BurpExtender.this.logTable.getColumnModel().getColumn(1).setPreferredWidth(30); // 低权限数据包2的改动, 减少一下请求类型的长度
             BurpExtender.this.logTable.getColumnModel().getColumn(2).setPreferredWidth(300);
             JScrollPane scrollPane = new JScrollPane(BurpExtender.this.logTable);
 
             
             JPanel jp = new JPanel();
             jp.setLayout(new GridLayout(1, 1));
             jp.add(scrollPane);
 
             
             JPanel jps = new JPanel();
             jps.setLayout(new GridLayout(10, 1));
             JLabel jls = new JLabel("插件名：瞎越 author：算命縖子");
             JLabel jls_1 = new JLabel("吐司:www.t00ls.com");
             JLabel jls_2 = new JLabel("版本：xia Yue V" + BurpExtender.this.xy_version);
             JLabel jls_3 = new JLabel("感谢名单：Moonlit");
             final JCheckBox chkbox1 = new JCheckBox("启动插件");
             final JCheckBox chkbox2 = new JCheckBox("启动万能cookie");
             JLabel jls_5 = new JLabel("如果需要多个域名加白请用,隔开");
             final JTextField textField = new JTextField("填写白名单域名");
 
 
             
             JButton btn1 = new JButton("清空列表");
             final JButton btn3 = new JButton("启动白名单");
 
 
 
             
             JPanel jps_2 = new JPanel();
             JLabel jps_2_jls_1 = new JLabel("越权：填写低权限认证信息,将会替换或新增");
             final JTextArea jta = new JTextArea("Cookie: JSESSIONID=test;UUID=1; userid=admin\nAuthorization: Bearer test", 5, 30);
             
             JScrollPane jsp = new JScrollPane(jta);
 
             
             JLabel jps_2_jls_2 = new JLabel("未授权：将移除下列头部认证信息,区分大小写");
             final JTextArea jta_1 = new JTextArea("Cookie\nAuthorization\nToken", 5, 30);
             
             JScrollPane jsp_1 = new JScrollPane(jta_1);



             jps_2.add(jps_2_jls_1);
             jps_2.add(jsp);
             jps_2.add(jps_2_jls_2);
             jps_2.add(jsp_1);

                        // 低权限数据包2的改动, 配置区
                        JLabel d2_label = new JLabel("越权(对应低数据权限2)：填写低权限认证信息,将会替换或新增");
                        final JTextArea d2_jta = new JTextArea("Cookie: JSESSIONID=test;UUID=2; userid=normal\nAuthorization: Bearer test", 5, 30);
                        JScrollPane d2_jsp = new JScrollPane(d2_jta);
                        jps_2.add(d2_label);
                        jps_2.add(d2_jsp);
 
             
             jps_2.setLayout(new GridLayout(7, 1, 0, 0)); // 低权限数据包2的改动, 5增加到7
 
 
 
             
             chkbox1.addItemListener(new ItemListener()
                 {
                   public void itemStateChanged(ItemEvent e) {
                     if (chkbox1.isSelected()) {
                       BurpExtender.this.switchs = 1;
                       
                       BurpExtender.this.data_1 = jta.getText();
                       BurpExtender.this.data_2 = jta_1.getText();
                                BurpExtender.this.data_d2 = d2_jta.getText(); // 低权限数据包2的改动, 配置区
                       
                       jta.setForeground(Color.BLACK);
                       jta.setBackground(Color.LIGHT_GRAY);
                       jta.setEditable(false);
                       
                       jta_1.setForeground(Color.BLACK);
                       jta_1.setBackground(Color.LIGHT_GRAY);
                       jta_1.setEditable(false);
                                // 低权限数据包2的改动, 配置区
                                d2_jta.setForeground(Color.BLACK);
                                d2_jta.setBackground(Color.LIGHT_GRAY);
                                d2_jta.setEditable(false);
                     } else {
                       BurpExtender.this.switchs = 0;
                       
                       jta.setForeground(Color.BLACK);
                       jta.setBackground(Color.WHITE);
                       jta.setEditable(true);
                       
                       jta_1.setForeground(Color.BLACK);
                       jta_1.setBackground(Color.WHITE);
                       jta_1.setEditable(true);
                                // 低权限数据包2的改动, 配置区
                                d2_jta.setForeground(Color.BLACK);
                                d2_jta.setBackground(Color.WHITE);
                                d2_jta.setEditable(true);
                     } 
                   }
                 });
 
             
             chkbox2.addItemListener(new ItemListener()
                 {
                   public void itemStateChanged(ItemEvent e) {
                     if (chkbox2.isSelected()) {
                       BurpExtender.this.universal_cookie = "";
                     } else {
                       BurpExtender.this.universal_cookie = "";
                     } 
                   }
                 });
 
             
             btn1.addActionListener(new ActionListener()
                 {
                   public void actionPerformed(ActionEvent e) {
                     BurpExtender.this.log.clear();
                     BurpExtender.this.conut = 0;
                     BurpExtender.this.log4_md5.clear();
                     BurpExtender.this.fireTableRowsInserted(BurpExtender.this.log.size(), BurpExtender.this.log.size());
                   }
                 });
             btn3.addActionListener(new ActionListener()
                 {
                   public void actionPerformed(ActionEvent e) {
                     if (btn3.getText().equals("启动白名单")) {
                       btn3.setText("关闭白名单");
                       BurpExtender.this.white_URL = textField.getText();
                       BurpExtender.this.white_switchs = 1;
                       textField.setEditable(false);
                       textField.setForeground(Color.GRAY);
                     } else {
                       btn3.setText("启动白名单");
                       BurpExtender.this.white_switchs = 0;
                       textField.setEditable(true);
                       textField.setForeground(Color.BLACK);
                     } 
                   }
                 });
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
             
             jps.add(jls);
             jps.add(jls_1);
             jps.add(jls_2);
             jps.add(jls_3);
             jps.add(chkbox1);
             
             jps.add(btn1);
             jps.add(jls_5);
             jps.add(textField);
             jps.add(btn3);
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
             
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
             
             JSplitPane y_jp = new JSplitPane(1);
             y_jp.setDividerLocation(500);
             y_jp.setLeftComponent(BurpExtender.this.requestViewer.getComponent());
             y_jp.setRightComponent(BurpExtender.this.responseViewer.getComponent());
             
             JSplitPane d_jp = new JSplitPane(1);
             d_jp.setDividerLocation(500);
             d_jp.setLeftComponent(BurpExtender.this.requestViewer_1.getComponent());
             d_jp.setRightComponent(BurpExtender.this.responseViewer_1.getComponent());
             
             JSplitPane w_jp = new JSplitPane(1);
             w_jp.setDividerLocation(500);
             w_jp.setLeftComponent(BurpExtender.this.requestViewer_2.getComponent());
             w_jp.setRightComponent(BurpExtender.this.responseViewer_2.getComponent());

                        // 低权限数据包2的改动, 请求,响应区域
                        JSplitPane d2_jp = new JSplitPane(1);
                        d2_jp.setDividerLocation(500);
                        d2_jp.setLeftComponent(BurpExtender.this.requestViewer_3.getComponent());
                        d2_jp.setRightComponent(BurpExtender.this.responseViewer_3.getComponent());
             
             BurpExtender.this.tabs.addTab("原始数据包", y_jp);
             BurpExtender.this.tabs.addTab("低权限数据包", d_jp);
             BurpExtender.this.tabs.addTab("未授权数据包", w_jp);
                      // 低权限数据包2的改动, 请求,响应区域
                      BurpExtender.this.tabs.addTab("低权限数据包2", d2_jp);
 
 
 
 
 
 
 
 
 
             
             splitPanes_2.setLeftComponent(jps);
             splitPanes_2.setRightComponent(jps_2);
 
             
             splitPanes.setLeftComponent(jp);
             splitPanes.setRightComponent(BurpExtender.this.tabs);
 
             
             BurpExtender.this.splitPane.setLeftComponent(splitPanes);
             BurpExtender.this.splitPane.setRightComponent(splitPanes_2);
             BurpExtender.this.splitPane.setDividerLocation(1000);
 
             
             callbacks.customizeUiComponent(BurpExtender.this.splitPane);
             callbacks.customizeUiComponent(BurpExtender.this.logTable);
             callbacks.customizeUiComponent(scrollPane);
             callbacks.customizeUiComponent(jps);
             callbacks.customizeUiComponent(jp);
             callbacks.customizeUiComponent(BurpExtender.this.tabs);
 
             
             callbacks.addSuiteTab(BurpExtender.this);
 
             
             callbacks.registerHttpListener(BurpExtender.this);
             callbacks.registerScannerCheck(BurpExtender.this);
           }
         });
   }
 
 
 
 
   
   public String getTabCaption() {
     return "xia Yue魔改版";
   }
 
 
   
   public Component getUiComponent() {
     return this.splitPane;
   }
 
 
 
 
   
   public void processHttpMessage(final int toolFlag, boolean messageIsRequest, final IHttpRequestResponse messageInfo) {
     if (this.switchs == 1 && 
       toolFlag == 4)
     {
       if (!messageIsRequest)
       {
         
         synchronized (this.log) {
 
           
           Thread thread = new Thread(new Runnable() {
                 public void run() {
                   try {
                     BurpExtender.this.checkVul(messageInfo, toolFlag);
                   } catch (Exception ex) {
                     ex.printStackTrace();
                     BurpExtender.this.stdout.println(ex);
                   } 
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
     this.temp_data = String.valueOf(this.helpers.analyzeRequest(baseRequestResponse).getUrl());
     this.original_data_len = (baseRequestResponse.getResponse()).length;
     int original_len = this.original_data_len - this.helpers.analyzeResponse(baseRequestResponse.getResponse()).getBodyOffset();
     String[] temp_data_strarray = this.temp_data.split("\\?");
     String temp_data = temp_data_strarray[0];
 
     
     String[] white_URL_list = this.white_URL.split(",");
     int white_swith = 0;
     if (this.white_switchs == 1) {
       white_swith = 0;
       for (int k = 0; k < white_URL_list.length; k++) {
         if (temp_data.contains(white_URL_list[k])) {
           this.stdout.println("白名单URL！" + temp_data);
           white_swith = 1;
         } 
       } 
       if (white_swith == 0) {
         this.stdout.println("不是白名单URL！" + temp_data);
         
         return;
       } 
     } 
     
     if (toolFlag == 4 || toolFlag == 64) {
       String[] static_file = { "jpg", "png", "gif", "css", "js", "pdf", "mp3", "mp4", "avi", "map", "svg", "ico", "svg", "woff", "woff2", "ttf" };
       String[] static_file_1 = temp_data.split("\\.");
       String static_file_2 = static_file_1[static_file_1.length - 1];
       for (String str : static_file) {
         if (static_file_2.equals(str)) {
           this.stdout.println("当前url为静态文件：" + temp_data + "\n");
 
           
           return;
         } 
       } 
     } 
     
     List<IParameter> paraLists = this.helpers.analyzeRequest(baseRequestResponse).getParameters();
     for (IParameter para : paraLists) {
       temp_data = temp_data + "+" + para.getName();
     }
 
     
     temp_data = temp_data + "+" + this.helpers.analyzeRequest(baseRequestResponse).getMethod();
     this.stdout.println("\nMD5(\"" + temp_data + "\")");
     temp_data = MD5(temp_data);
     this.stdout.println(temp_data);
     
     for (Request_md5 request_md5 : this.log4_md5) {
       if (request_md5.md5_data.equals(temp_data)) {
         return;
       }
     } 
     this.log4_md5.add(new Request_md5(temp_data));
 
 
 
     
     IRequestInfo analyIRequestInfo = this.helpers.analyzeRequest(baseRequestResponse);
     IHttpService iHttpService = baseRequestResponse.getHttpService();
     String request = this.helpers.bytesToString(baseRequestResponse.getRequest());
     int bodyOffset = analyIRequestInfo.getBodyOffset();
     byte[] body = request.substring(bodyOffset).getBytes();
 
 
     
     List<String> headers_y = analyIRequestInfo.getHeaders();
     
     String[] data_1_list = this.data_1.split("\n"); int i;
     for (i = 0; i < headers_y.size(); i++) {
       String head_key = ((String)headers_y.get(i)).split(":")[0];
       for (int y = 0; y < data_1_list.length; y++) {
         if (head_key.equals(data_1_list[y].split(":")[0])) {
           headers_y.remove(i);
           i--;
         } 
       } 
     } 
 
     
     for (i = 0; i < data_1_list.length; i++) {
       headers_y.add(headers_y.size() / 2, data_1_list[i]);
     }
 
     
     byte[] newRequest_y = this.helpers.buildHttpMessage(headers_y, body);
     IHttpRequestResponse requestResponse_y = this.callbacks.makeHttpRequest(iHttpService, newRequest_y);
     int low_len = (requestResponse_y.getResponse()).length - this.helpers.analyzeResponse(requestResponse_y.getResponse()).getBodyOffset();
     String low_len_data = "";
     if (original_len == 0) {
       low_len_data = Integer.toString(low_len);
     } else if (original_len == low_len) {
       low_len_data = Integer.toString(low_len) + "  ✔";
     } else {
       low_len_data = Integer.toString(low_len) + "  ==> " + Integer.toString(original_len - low_len);
     }

    // 低权限数据包2的改动, 修改头,发送请求
    List<String> headers_d2 = analyIRequestInfo.getHeaders();
     String[] data_d2_list = this.data_d2.split("\n"); int k;
     for (k = 0; k < headers_d2.size(); k++) {
       String head_key = ((String)headers_d2.get(k)).split(":")[0];
       for (int y = 0; y < data_d2_list.length; y++) {
         if (head_key.equals(data_d2_list[y].split(":")[0])) {
           headers_d2.remove(k);
           k--;
         }
       }
     }


     for (k = 0; k < data_d2_list.length; k++) {
       headers_d2.add(headers_d2.size() / 2, data_d2_list[k]);
     }

     byte[] newRequest_d2 = this.helpers.buildHttpMessage(headers_d2, body);
     IHttpRequestResponse requestResponse_d2 = this.callbacks.makeHttpRequest(iHttpService, newRequest_d2);
     int low2_len = (requestResponse_d2.getResponse()).length - this.helpers.analyzeResponse(requestResponse_d2.getResponse()).getBodyOffset();
     String low2_len_data = "";
     if (original_len == 0) {
       low2_len_data = Integer.toString(low2_len);
     } else if (original_len == low2_len) {
       low2_len_data = Integer.toString(low2_len) + "  ✔";
     } else {
       low2_len_data = Integer.toString(low2_len) + "  ==> " + Integer.toString(original_len - low2_len);
     }


     
     List<String> headers_w = analyIRequestInfo.getHeaders();
     
     String[] data_2_list = this.data_2.split("\n");
     for (int j = 0; j < headers_w.size(); j++) {
       String head_key = ((String)headers_w.get(j)).split(":")[0];
       for (int y = 0; y < data_2_list.length; y++) {
         if (head_key.equals(data_2_list[y])) {
           headers_w.remove(j);
           j--;
         } 
       } 
     } 
     
     if (this.universal_cookie.length() != 0) {
       String[] universal_cookies = this.universal_cookie.split("\n");
       headers_w.add(headers_w.size() / 2, universal_cookies[0]);
       headers_w.add(headers_w.size() / 2, universal_cookies[1]);
     } 
     
     byte[] newRequest_w = this.helpers.buildHttpMessage(headers_w, body);
     IHttpRequestResponse requestResponse_w = this.callbacks.makeHttpRequest(iHttpService, newRequest_w);
     int Unauthorized_len = (requestResponse_w.getResponse()).length - this.helpers.analyzeResponse(requestResponse_w.getResponse()).getBodyOffset();
     String original_len_data = "";
     if (original_len == 0) {
       original_len_data = Integer.toString(Unauthorized_len);
     } else if (original_len == Unauthorized_len) {
       original_len_data = Integer.toString(Unauthorized_len) + "  ✔";
     } else {
       original_len_data = Integer.toString(Unauthorized_len) + "  ==> " + Integer.toString(original_len - Unauthorized_len);
     } 
 
     
     int id = ++this.conut;
            // 低权限数据包2的改动, 调整了LogEntry构造方法
     this.log.add(new LogEntry(id, this.helpers.analyzeRequest(baseRequestResponse).getMethod(), this.callbacks.saveBuffersToTempFiles(baseRequestResponse), this.callbacks.saveBuffersToTempFiles(requestResponse_y), this.callbacks.saveBuffersToTempFiles(requestResponse_w), this.callbacks.saveBuffersToTempFiles(requestResponse_d2), String.valueOf(this.helpers.analyzeRequest(baseRequestResponse).getUrl()), original_len, low_len_data, original_len_data, low2_len_data));
 
 
 
     
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
         return Integer.valueOf(logEntry.id);
       case 1:
         return logEntry.Method;
       case 2:
         return logEntry.url;
       case 3:
         return Integer.valueOf(logEntry.original_len);
       case 4:
         return logEntry.low_len;
       case 5:
         return logEntry.Unauthorized_len;
                case 6: // 低权限数据包2的改动, 表格增加了一列, 6改成7
                  return logEntry.low2_len_data;
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
     extends JTable
   {
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
       
       BurpExtender.this.requestViewer.setMessage(logEntry.requestResponse.getRequest(), true);
       BurpExtender.this.responseViewer.setMessage(logEntry.requestResponse.getResponse(), false);
       BurpExtender.this.currentlyDisplayedItem = logEntry.requestResponse;
       BurpExtender.this.requestViewer_1.setMessage(logEntry.requestResponse_1.getRequest(), true);
       BurpExtender.this.responseViewer_1.setMessage(logEntry.requestResponse_1.getResponse(), false);
       BurpExtender.this.currentlyDisplayedItem_1 = logEntry.requestResponse_1;
       BurpExtender.this.requestViewer_2.setMessage(logEntry.requestResponse_2.getRequest(), true);
       BurpExtender.this.responseViewer_2.setMessage(logEntry.requestResponse_2.getResponse(), false);
       BurpExtender.this.currentlyDisplayedItem_2 = logEntry.requestResponse_2;
    // 低权限数据包2的改动,
    BurpExtender.this.requestViewer_3.setMessage(logEntry.requestResponse_3.getRequest(), true);
    BurpExtender.this.responseViewer_3.setMessage(logEntry.requestResponse_3.getResponse(), false);
    BurpExtender.this.currentlyDisplayedItem_3 = logEntry.requestResponse_3;
       
       super.changeSelection(row, col, toggle, extend);
     }
   }
 
   
   private static class Request_md5
   {
     final String md5_data;
 
     
     Request_md5(String md5_data) {
       this.md5_data = md5_data;
     }
   }
 
   
   private static class LogEntry
   {
     final int id;
     
     final String Method;
     
     final IHttpRequestResponsePersisted requestResponse;
     final IHttpRequestResponsePersisted requestResponse_1;
     final IHttpRequestResponsePersisted requestResponse_2;
              final IHttpRequestResponsePersisted requestResponse_3; // 低权限数据包2的改动,
     final String url;
     final int original_len;
     final String low_len;
     final String Unauthorized_len;
              final String low2_len_data; // 低权限数据包2的改动,

                // 低权限数据包2的改动, 调整了构造方法入参
     LogEntry(int id, String Method, IHttpRequestResponsePersisted requestResponse, IHttpRequestResponsePersisted requestResponse_1, IHttpRequestResponsePersisted requestResponse_2, IHttpRequestResponsePersisted requestResponse_3, String url, int original_len, String low_len, String Unauthorized_len, String low2_len_data) {
       this.id = id;
       this.Method = Method;
       this.requestResponse = requestResponse;
       this.requestResponse_1 = requestResponse_1;
       this.requestResponse_2 = requestResponse_2;
                this.requestResponse_3 = requestResponse_3; // 低权限数据包2的改动,
       this.url = url;
       this.original_len = original_len;
       this.low_len = low_len;
       this.Unauthorized_len = Unauthorized_len;
                this.low2_len_data = low2_len_data; // 低权限数据包2的改动,
     }
   }
 
   
   public static String MD5(String key) {
     char[] hexDigits = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
 
     
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
