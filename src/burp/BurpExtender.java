package burp;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.Font;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;
import java.util.List;
import javax.swing.border.EmptyBorder;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.text.BadLocationException;
import javax.swing.text.DefaultHighlighter;
import javax.swing.text.Highlighter.Highlight;
import javax.swing.text.Highlighter.HighlightPainter;
import javax.swing.text.Highlighter;

public class BurpExtender implements IBurpExtender, ITab, IContextMenuFactory, ActionListener {
    
    private char delimiter;
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private IHttpRequestResponse[] selectedItems;
    private JButton btnScan;
    private JButton btnSetMarker;
    private JButton btnUnsetMarker;
    private JCheckBox chkHttps;
    private JLabel lblResult;
    private JPanel skenpotScannerPanel;
    private JTabbedPane skenpotPanel;
    private JTextArea txtRequest;
    private JTextField txtHost;
    private JTextField txtPort;
    
    static final String[] HOSTNAMES = {"localhost", "127.0.0.1", "2130706433", "0x7F000001", "[::1]"};
    static final String[] TEMPLATES = {"IP:PORT", "IP:PORT:DEFAULT", "foo:bar@IP:PORT@google.com"};
    
    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
    {
        this.callbacks = callbacks;
        helpers = callbacks.getHelpers();
        
        // Set the extension name
        callbacks.setExtensionName("Skenpot");
        
        callbacks.registerContextMenuFactory(this);
        
        delimiter = (char)167;
        
        SwingUtilities.invokeLater(new Runnable()
        {
            @Override   
            public void run()
            {
            	skenpotPanel = new JTabbedPane();
                
            	// SCANNER TAB
                skenpotScannerPanel = new JPanel();
                skenpotScannerPanel.setLayout(new BorderLayout());
                
                // SCANNER TAB - TOP
                JPanel topPanelScanner = new JPanel();
                topPanelScanner.setLayout(new BoxLayout(topPanelScanner, BoxLayout.X_AXIS));
                topPanelScanner.setBorder(new EmptyBorder(10, 40, 20, 10));
                
                // SCANNER TAB - TOP - SETTINGS
                JPanel topPanelScannerSetting = new JPanel();
                topPanelScannerSetting.setLayout(new BoxLayout(topPanelScannerSetting, BoxLayout.X_AXIS));
                
                String description = "<html><p><b><font color=\"#E38A1A\" face=\"arial\" size=\"5\">Skenpot</font></b></p><p>This burp extender is for <b>Server-Side Request Forgery (SSRF)</b> vulnerability.</p></html>";
                topPanelScannerSetting.add(new JLabel(description));
                
                // SCANNER TAB - TOP - SCAN
                JPanel topPanelScannerScan = new JPanel();
                topPanelScannerScan.setLayout(new BoxLayout(topPanelScannerScan, BoxLayout.X_AXIS));
                
                btnScan = new JButton("Start scan");
                btnScan.setActionCommand("doScan");
                btnScan.addActionListener(BurpExtender.this);
                btnScan.setFont(new Font(btnScan.getFont().getName(), Font.BOLD, btnScan.getFont().getSize()));
                topPanelScannerScan.add(btnScan);
                
                topPanelScanner.add(topPanelScannerSetting);
                topPanelScanner.add(topPanelScannerScan);
                
                // SCANNER TAB - BOTTOM
                JPanel bottomPanelScanner = new JPanel();
                bottomPanelScanner.setLayout(new BoxLayout(bottomPanelScanner, BoxLayout.Y_AXIS));
                
                // SCANNER TAB - BOTTOM - LEFT
                JPanel bottomPanelScannerLeft = new JPanel();
                bottomPanelScannerLeft.setLayout(new BoxLayout(bottomPanelScannerLeft, BoxLayout.Y_AXIS));
                bottomPanelScannerLeft.setBorder(new EmptyBorder(0, 40, 40, 10));
                
                // SCANNER TAB - BOTTOM - LEFT - SETTINGS
                JPanel bottomPanelScannerLeftSettings = new JPanel();
                bottomPanelScannerLeftSettings.setLayout(new BoxLayout(bottomPanelScannerLeftSettings, BoxLayout.X_AXIS));
                //bottomPanelScannerLeftSettings.setBackground(new Color(226, 224, 224));
                
                txtHost = new JTextField();
                bottomPanelScannerLeftSettings.add(new JLabel("Host: "));
                bottomPanelScannerLeftSettings.add(txtHost);
                
                bottomPanelScannerLeftSettings.add(Box.createVerticalStrut(20));
                
                txtPort = new JTextField();
                bottomPanelScannerLeftSettings.add(new JLabel("Port: "));
                bottomPanelScannerLeftSettings.add(txtPort);
                
                bottomPanelScannerLeftSettings.add(Box.createVerticalStrut(20));
                
                chkHttps = new JCheckBox();
                bottomPanelScannerLeftSettings.add(new JLabel("Use HTTPS "));
                bottomPanelScannerLeftSettings.add(chkHttps);
                
                bottomPanelScannerLeft.add(bottomPanelScannerLeftSettings, BorderLayout.WEST);
                
                
                // SCANNER TAB - BOTTOM - REQUEST
                JPanel bottomPanelScannerRequest = new JPanel();
                bottomPanelScannerRequest.setLayout(new BoxLayout(bottomPanelScannerRequest, BoxLayout.Y_AXIS));
                bottomPanelScannerRequest.setBorder(new EmptyBorder(10, 0, 20, 0));
                                
                txtRequest = new JTextArea(40, 80);
                JScrollPane scrollRequestAreaManualTesting = new JScrollPane(txtRequest);
                txtRequest.setLineWrap(true);
                scrollRequestAreaManualTesting.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
                bottomPanelScannerRequest.add(scrollRequestAreaManualTesting);
                
                bottomPanelScannerLeft.add(bottomPanelScannerRequest);
                
                // SCANNER TAB - BOTTOM - TOOLS
                JPanel bottomPanelScannerTool = new JPanel();
                bottomPanelScannerTool.setLayout(new BoxLayout(bottomPanelScannerTool, BoxLayout.X_AXIS));
                
                lblResult = new JLabel(BurpExtender.setProgress("Ready!"));
                bottomPanelScannerTool.add(lblResult);
                
                btnSetMarker = new JButton("Add §");
                btnSetMarker.setActionCommand("setMark");
                btnSetMarker.addActionListener(BurpExtender.this);
                bottomPanelScannerTool.add(btnSetMarker);
                
                btnUnsetMarker = new JButton("Clear §");
                btnUnsetMarker.setActionCommand("unsetMark");
                btnUnsetMarker.addActionListener(BurpExtender.this);
                bottomPanelScannerTool.add(btnUnsetMarker);
                
                bottomPanelScannerLeft.add(bottomPanelScannerTool);
                
                bottomPanelScanner.add(bottomPanelScannerLeft);
                
                JSplitPane skenpotScannerSplitter = new JSplitPane( JSplitPane.VERTICAL_SPLIT, topPanelScanner, bottomPanelScanner );
                skenpotScannerSplitter.setEnabled(true);
                skenpotScannerSplitter.setDividerSize(0);
                
                skenpotScannerPanel.add(skenpotScannerSplitter);
                
                // Add the custom tab to Burp's UI
                skenpotPanel.addTab("Scanner", skenpotScannerPanel);
                
                callbacks.addSuiteTab(BurpExtender.this);
                
            }
        });
    }
    
    public static String setProgress(String message) {
        return "<html><b>STATUS</b>: " + message + "</html>";
    }
    
    public void doScan() {
        if (!txtRequest.getText().trim().equals("")) {
            
            String port = "";

            try {
                port = Integer.toString(Integer.parseInt(txtPort.getText().trim()));
            } catch(NumberFormatException e) {
                port = (chkHttps.isSelected()) ? "443" : "80";
            }

            long duration = 0;
            boolean resultFound = false;
            boolean hasMarkerOnRequest = false;

            String strRequest = txtRequest.getText();
            int sMarker = strRequest.indexOf(delimiter);
            int lMarker = strRequest.lastIndexOf(delimiter);

            if (sMarker != lMarker) {
                hasMarkerOnRequest = true;
                IHttpService httpService = helpers.buildHttpService(txtHost.getText().trim(), Integer.parseInt(port), chkHttps.isSelected());

                String firstHalfRequest  =  strRequest.substring(0, sMarker);
                String secondHalfRequest = strRequest.substring(lMarker + 1, strRequest.length());

                String sample = "";

                for (String template : BurpExtender.TEMPLATES) {
                    if (template.equals("IP:PORT"))
                        lblResult.setText(BurpExtender.setProgress("Trying Basic Method"));
                    if (template.equals("IP:PORT:DEFAULT"))
                        lblResult.setText(BurpExtender.setProgress("Trying Double Port"));
                    if (template.equals("foo:bar@IP:PORT@google.com"))
                        lblResult.setText(BurpExtender.setProgress("Trying URL Parsing Issue"));

                    for (String hostname : BurpExtender.HOSTNAMES) {
                        for (int phases = 0; phases < 2; phases++) {
                            // ZERO is the TRUE request, NON-ZERO is the FALSE request
                            if (phases % 2 == 0) {
                                sample  = template.replaceAll("IP", hostname).replaceAll("PORT", port).replaceAll("DEFAULT", port);
                            } else {
                                sample = template.replaceAll("IP", hostname).replaceAll("PORT", "1").replaceAll("DEFAULT", port);
                            }
                            
                            byte[] request = (firstHalfRequest + sample + secondHalfRequest).getBytes();

                            IRequestInfo requestInfo = helpers.analyzeRequest(request);
                            List<String> headers = requestInfo.getHeaders();
                            byte[] body = Arrays.copyOfRange(request, requestInfo.getBodyOffset(), request.length);
                            request = helpers.buildHttpMessage(headers, body); 			

                            long temp = System.nanoTime();
                            callbacks.makeHttpRequest(httpService, request);

                            if (phases % 2 == 0) {
                                duration = TimeUnit.MILLISECONDS.convert((System.nanoTime() - temp), TimeUnit.NANOSECONDS);
                            } else {
                                long timeGap = TimeUnit.MILLISECONDS.convert((System.nanoTime() - temp), TimeUnit.NANOSECONDS) - duration;

                                // Should consider VULNERABLE! :)
                                if (timeGap > 1000) {
                                    resultFound = true;

                                    if (template.equals("IP:PORT"))
                                        lblResult.setText(BurpExtender.setProgress("Vulnerable - <b>Basic Method</b>!"));
                                    if (template.equals("IP:PORT:DEFAULT"))
                                        lblResult.setText(BurpExtender.setProgress("Vulnerable - <b>Double Port</b>!"));
                                    if (template.equals("foo:bar@IP:PORT@google.com"))
                                        lblResult.setText(BurpExtender.setProgress("Vulnerable - <b>URL Parsing Issue</b>!"));

                                    break;
                                }
                            }
                        }
                    }

                    if (resultFound) {
                        break;
                    }
                }
            } else {
                lblResult.setText(BurpExtender.setProgress("Please mark the hostname's location which you want to scan."));
            }

            if (!hasMarkerOnRequest) {
                lblResult.setText(BurpExtender.setProgress("Please mark the hostname's location which you want to scan."));
            } else {
                if (!resultFound) {
                    lblResult.setText(BurpExtender.setProgress("NOT VULNERABLE :("));
                }
            }
        } else {
            lblResult.setText(BurpExtender.setProgress("There is nothing to be scanned."));
        }
    }
    
    public void setMark() {
        int sOffset = 0;
        int lOffset = 0;
        
        boolean textIsHighlighted = true;
        
        Highlighter highlighter = txtRequest.getHighlighter();
        Highlight[] highlights  = highlighter.getHighlights();
        
        if (highlights.length == 0) {
            if(txtRequest.getSelectedText() != null && !txtRequest.getSelectedText().isEmpty()) {
                sOffset = txtRequest.getText().indexOf(txtRequest.getSelectedText());
                lOffset = sOffset + txtRequest.getSelectedText().length();
            } else {
                textIsHighlighted = false;
            }
        } else {
            sOffset = highlights[0].getStartOffset();
            lOffset = highlights[0].getEndOffset();
        }
        
        if (textIsHighlighted) {
            String strRequest = txtRequest.getText();        
            txtRequest.setText(strRequest.substring(0, sOffset) + delimiter + strRequest.substring(sOffset, lOffset) + delimiter + strRequest.substring(lOffset, strRequest.length()));

            // Clear all and re-add all highlighters! ;)
            highlighter.removeAllHighlights();

            // Set highlighter to PINK.
            HighlightPainter painter = new DefaultHighlighter.DefaultHighlightPainter(Color.pink);

            try {
                highlighter.addHighlight(sOffset, lOffset + 2, painter);
            } catch (BadLocationException e) {}
        }
    }
    
    public void unsetMark() {
        txtRequest.setText(txtRequest.getText().replace(String.valueOf(delimiter), ""));
        
        // Remove ALL highlighted texts.
        Highlighter highlighter = txtRequest.getHighlighter();
        highlighter.removeAllHighlights();
    }
    
    public void toSkenpot() {
        IHttpService httpService = selectedItems[0].getHttpService();
        byte[] request = selectedItems[0].getRequest();
        
        // Set Skenpot with details from passed request
        txtRequest.setText(new String(request));
        txtHost.setText(httpService.getHost());
        txtPort.setText(Integer.toString(httpService.getPort()));
		
        if(httpService.getProtocol().equals("https")) {
                chkHttps.setSelected(true);
        } else {
                chkHttps.setSelected(false);
        }
        
        Highlighter highlighter = txtRequest.getHighlighter();
        highlighter.removeAllHighlights();
        lblResult.setText(BurpExtender.setProgress("Ready!"));
    }
    
    @Override
    public void actionPerformed(ActionEvent event) {
        String command = event.getActionCommand();
        
        if (command.equals("setMark")) {
            setMark();
        } else if (command.equals("unsetMark")) {
            unsetMark();
        } else if(command.equals("doScan")) {
            // Start scanning...
            lblResult.setText("Scanning in progress..");
            Thread t = new Thread() {
                public void run() {
                    doScan();
                }
            };
            t.start();
            
        } else if(command.equals("doExploit")) {
            // something
        } else if(command.equals("toSkenpot")) {
            toSkenpot();
        }
    }
    
    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        selectedItems = invocation.getSelectedMessages();
        
        JMenuItem item = new JMenuItem("Send request to Skenpot (SSRF Scanner)");
        item.setActionCommand("toSkenpot");
        item.addActionListener(this);
        
        List<JMenuItem> menu = Arrays.asList(item);
        
        return menu;
    }

    @Override
    public String getTabCaption() {
        return "Skenpot";
    }
    
    @Override
    public Component getUiComponent() {
        return skenpotPanel;
    }
}
