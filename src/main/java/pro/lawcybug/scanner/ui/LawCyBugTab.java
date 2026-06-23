package pro.lawcybug.scanner.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import pro.lawcybug.scanner.core.DetectorEngine;
import pro.lawcybug.scanner.core.Finding;
import pro.lawcybug.scanner.core.FindingsStore;
import pro.lawcybug.scanner.core.ScanSettings;
import pro.lawcybug.scanner.rules.CustomRuleEngine;
import pro.lawcybug.scanner.workflow.IdentityRegistry;
import pro.lawcybug.scanner.workflow.SessionIdentity;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.event.ListSelectionListener;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Main Burp Suite extension tab registered via api.userInterface().registerSuiteTab().
 * Contains three sub-tabs: Dashboard (live findings feed), Settings
 * (per-detector toggles + global options) and Rules (custom JSON rule manager).
 */
public final class LawCyBugTab {

    // ── Header brand colour palette ──────────────────────────────────────────
    private static final Color BRAND_BG       = new Color(0x1A, 0x1A, 0x2E);  // deep navy
    private static final Color BRAND_ACCENT   = new Color(0x0F, 0xC4, 0xB6);  // cyan
    private static final Color BRAND_ACCENT2  = new Color(0xE9, 0x45, 0x60);  // red
    private static final Color BRAND_FG       = new Color(0xE8, 0xE8, 0xE8);  // near-white
    private static final Color PANEL_BG       = new Color(0x1E, 0x1E, 0x30);
    private static final Color ROW_HIGH       = new Color(0x25, 0x25, 0x40);

    private final MontoyaApi         api;
    private final FindingsStore       store;
    private final ScanSettings        settings;
    private final DetectorEngine      engine;
    private final CustomRuleEngine    ruleEngine;
    private final IdentityRegistry    identityRegistry;

    private JPanel rootPanel;
    private FindingsTableModel tableModel;
    private JTable findingsTable;
    private TableRowSorter<FindingsTableModel> rowSorter;
    private JTextField searchField;
    private JComboBox<String> severityFilter;
    private JComboBox<String> statusFilter;

    // Request/response evidence viewer (Dashboard tab)
    private HttpRequestEditor requestEditor;
    private HttpResponseEditor responseEditor;
    private JComboBox<String> evidenceSelector;
    private JPanel evidenceCardPanel;
    private static final String CARD_EMPTY  = "empty";
    private static final String CARD_VIEWER = "viewer";
    private List<HttpRequestResponse> currentEvidence = List.of();

    public LawCyBugTab(MontoyaApi api,
                        FindingsStore store,
                        ScanSettings settings,
                        DetectorEngine engine,
                        CustomRuleEngine ruleEngine,
                        IdentityRegistry identityRegistry) {
        this.api        = api;
        this.store      = store;
        this.settings   = settings;
        this.engine     = engine;
        this.ruleEngine = ruleEngine;
        this.identityRegistry = identityRegistry;
        buildUI();
    }

    public String caption() {
        return "LawCyBug.pro";
    }

    public Component uiComponent() {
        return rootPanel;
    }

    // ── Build ─────────────────────────────────────────────────────────────────
    private void buildUI() {
        rootPanel = new JPanel(new BorderLayout());
        rootPanel.setBackground(BRAND_BG);

        // Top header bar
        rootPanel.add(buildHeader(), BorderLayout.NORTH);

        // Sub-tab panel
        JTabbedPane tabs = new JTabbedPane();
        tabs.setBackground(PANEL_BG);
        tabs.setForeground(BRAND_FG);
        tabs.addTab("📊 Dashboard", buildDashboardPanel());
        tabs.addTab("⚙  Settings",  buildSettingsPanel());
        tabs.addTab("📋 Rules",      buildRulesPanel());
        tabs.addTab("🧑‍🤝‍🧑 Identities", buildIdentitiesPanel());
        rootPanel.add(tabs, BorderLayout.CENTER);
    }

    private JPanel buildHeader() {
        JPanel header = new JPanel(new BorderLayout());
        header.setBackground(BRAND_BG);
        header.setBorder(new EmptyBorder(12, 18, 12, 18));

        JLabel title = new JLabel("LawCyBug.pro");
        title.setForeground(BRAND_ACCENT);
        title.setFont(new Font("SansSerif", Font.BOLD, 22));

        JLabel subtitle = new JLabel("  Next-Generation Vulnerability Scanner | Authorised Bug Bounty");
        subtitle.setForeground(BRAND_FG);
        subtitle.setFont(new Font("SansSerif", Font.PLAIN, 12));

        JPanel left = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        left.setBackground(BRAND_BG);
        left.add(title);
        left.add(subtitle);

        JLabel version = new JLabel("v1.0.0  ⚡");
        version.setForeground(BRAND_ACCENT2);
        version.setFont(new Font("SansSerif", Font.BOLD, 12));

        header.add(left, BorderLayout.WEST);
        header.add(version, BorderLayout.EAST);
        return header;
    }

    // ── Dashboard tab ─────────────────────────────────────────────────────────
    private JPanel buildDashboardPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBackground(PANEL_BG);

        // Stats bar
        JPanel stats = new JPanel(new FlowLayout(FlowLayout.LEFT, 20, 8));
        stats.setBackground(BRAND_BG);
        JLabel totalLabel  = statLabel("Total: 0",  Color.WHITE);
        JLabel highLabel   = statLabel("🔴 High: 0", BRAND_ACCENT2);
        JLabel medLabel    = statLabel("🟠 Medium: 0", new Color(0xFF, 0x8C, 0x00));
        JLabel lowLabel    = statLabel("🟡 Low: 0",  new Color(0xFF, 0xD7, 0x00));
        stats.add(totalLabel); stats.add(highLabel); stats.add(medLabel); stats.add(lowLabel);

        // Filter/search toolbar
        JPanel filterBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 4));
        filterBar.setBackground(PANEL_BG);

        JLabel searchLbl = new JLabel("🔎");
        searchField = new JTextField(22);
        searchField.setToolTipText("Filter by detector, URL or issue name (regex supported)");
        filterBar.add(searchLbl);
        filterBar.add(searchField);

        JLabel sevLbl = new JLabel("Severity:");
        sevLbl.setForeground(BRAND_FG);
        severityFilter = new JComboBox<>(new String[]{"All", "HIGH", "MEDIUM", "LOW", "INFORMATION"});
        filterBar.add(sevLbl);
        filterBar.add(severityFilter);

        JLabel statusLbl = new JLabel("Status:");
        statusLbl.setForeground(BRAND_FG);
        statusFilter = new JComboBox<>(new String[]{"All", "New", "Reviewed", "False Positive"});
        filterBar.add(statusLbl);
        filterBar.add(statusFilter);

        JButton saveBtn = new JButton("💾 Save");
        saveBtn.setToolTipText("Persist findings now, so they survive an extension reload");
        saveBtn.addActionListener(e -> {
            store.persist(api);
            api.logging().logToOutput("[LawCyBug.pro] Findings saved (" + store.count() + ").");
        });
        styleButton(saveBtn);
        filterBar.add(saveBtn);

        JPanel north = new JPanel(new BorderLayout());
        north.setBackground(BRAND_BG);
        north.add(stats, BorderLayout.NORTH);
        north.add(filterBar, BorderLayout.SOUTH);
        panel.add(north, BorderLayout.NORTH);

        // Findings table
        tableModel = new FindingsTableModel();
        JTable table = new JTable(tableModel);
        findingsTable = table;
        table.setBackground(PANEL_BG);
        table.setForeground(BRAND_FG);
        table.setGridColor(new Color(0x33, 0x33, 0x55));
        table.setSelectionBackground(ROW_HIGH);
        table.setFont(new Font("Monospaced", Font.PLAIN, 12));
        table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        table.getTableHeader().setBackground(BRAND_BG);
        table.getTableHeader().setForeground(BRAND_ACCENT);
        table.getColumnModel().getColumn(0).setMaxWidth(70);
        table.getColumnModel().getColumn(1).setMaxWidth(80);
        table.getColumnModel().getColumn(2).setMaxWidth(90);
        table.getColumnModel().getColumn(5).setMaxWidth(110);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);
        table.setRowHeight(20);
        table.setDefaultRenderer(Object.class, new StatusAwareRenderer());

        rowSorter = new TableRowSorter<>(tableModel);
        table.setRowSorter(rowSorter);

        DocumentListener filterListener = new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e)  { applyFilters(); }
            @Override public void removeUpdate(DocumentEvent e)  { applyFilters(); }
            @Override public void changedUpdate(DocumentEvent e) { applyFilters(); }
        };
        searchField.getDocument().addDocumentListener(filterListener);
        severityFilter.addActionListener(e -> applyFilters());
        statusFilter.addActionListener(e -> applyFilters());

        // Right-click context menu: Send to Repeater + triage actions + copy URL
        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseReleased(MouseEvent e) {
                if (!e.isPopupTrigger()) return;
                int viewRow = table.rowAtPoint(e.getPoint());
                if (viewRow < 0) return;
                if (!table.isRowSelected(viewRow)) {
                    table.setRowSelectionInterval(viewRow, viewRow);
                }
                showContextMenu(table, e.getX(), e.getY());
            }
        });

        // Selecting row(s) loads the lead-selected finding's request/response below
        table.getSelectionModel().addListSelectionListener((ListSelectionListener) e -> {
            if (e.getValueIsAdjusting()) return;
            int viewRow = table.getSelectionModel().getLeadSelectionIndex();
            if (viewRow < 0 || viewRow >= table.getRowCount() || !table.isRowSelected(viewRow)) {
                showEvidence(List.of());
                return;
            }
            int modelRow = table.convertRowIndexToModel(viewRow);
            Finding finding = tableModel.getFinding(modelRow);
            showEvidence(finding.issue().requestResponses());
        });

        // Subscribe to new findings
        store.addListener(finding -> SwingUtilities.invokeLater(() -> {
            tableModel.addFinding(finding);
            refreshStats(totalLabel, highLabel, medLabel, lowLabel);
        }));
        refreshStats(totalLabel, highLabel, medLabel, lowLabel);

        JScrollPane scroll = new JScrollPane(table);
        scroll.setBackground(PANEL_BG);

        // Evidence viewer (request/response for the selected finding) below the table
        JPanel evidencePanel = buildEvidenceViewerPanel();

        JSplitPane verticalSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, scroll, evidencePanel);
        verticalSplit.setResizeWeight(0.35);
        verticalSplit.setBackground(PANEL_BG);
        verticalSplit.setBorder(null);
        panel.add(verticalSplit, BorderLayout.CENTER);

        // Clear button
        JButton clearBtn = new JButton("Clear");
        clearBtn.addActionListener(e -> {
            tableModel.clear();
            store.clear();
            showEvidence(List.of());
            refreshStats(totalLabel, highLabel, medLabel, lowLabel);
        });
        styleButton(clearBtn);
        JPanel south = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        south.setBackground(PANEL_BG);
        south.add(clearBtn);
        panel.add(south, BorderLayout.SOUTH);

        return panel;
    }

    private void refreshStats(JLabel totalLabel, JLabel highLabel, JLabel medLabel, JLabel lowLabel) {
        totalLabel.setText("Total: " + store.count());
        highLabel.setText("🔴 High: " + store.countBySeverity("HIGH"));
        medLabel.setText("🟠 Medium: " + store.countBySeverity("MEDIUM"));
        lowLabel.setText("🟡 Low: " + store.countBySeverity("LOW"));
    }

    /** Rebuilds the table's RowFilter from the search box + severity/status combos. */
    private void applyFilters() {
        String search = searchField.getText();
        String sevSel = (String) severityFilter.getSelectedItem();
        String statSel = (String) statusFilter.getSelectedItem();

        List<javax.swing.RowFilter<FindingsTableModel, Integer>> filters = new ArrayList<>();

        if (search != null && !search.isBlank()) {
            try {
                String regex = "(?i)" + Pattern.quote(search);
                // Columns 2 (Detector), 3 (URL), 4 (Issue Name)
                filters.add(javax.swing.RowFilter.regexFilter(regex, 2, 3, 4));
            } catch (PatternSyntaxException ignore) {
                // shouldn't happen since we quote(), but fail open rather than throw
            }
        }
        if (sevSel != null && !"All".equals(sevSel)) {
            filters.add(javax.swing.RowFilter.regexFilter("^" + Pattern.quote(sevSel) + "$", 1));
        }
        if (statSel != null && !"All".equals(statSel)) {
            filters.add(javax.swing.RowFilter.regexFilter("^" + Pattern.quote(statSel) + "$", 5));
        }

        rowSorter.setRowFilter(filters.isEmpty() ? null : javax.swing.RowFilter.andFilter(filters));
    }

    private void showContextMenu(JTable table, int x, int y) {
        int[] viewRows = table.getSelectedRows();
        List<Finding> selected = new ArrayList<>();
        for (int viewRow : viewRows) {
            selected.add(tableModel.getFinding(table.convertRowIndexToModel(viewRow)));
        }
        if (selected.isEmpty()) return;

        JPopupMenu menu = new JPopupMenu();

        JMenuItem sendToRepeater = new JMenuItem(
                selected.size() == 1 ? "Send to Repeater" : "Send " + selected.size() + " to Repeater");
        sendToRepeater.addActionListener(a -> sendToRepeater(selected));
        menu.add(sendToRepeater);

        menu.addSeparator();

        JMenuItem markReviewed = new JMenuItem("Mark Reviewed");
        markReviewed.addActionListener(a -> setStatus(selected, Finding.Status.REVIEWED));
        menu.add(markReviewed);

        JMenuItem markFalsePositive = new JMenuItem("Mark False Positive");
        markFalsePositive.addActionListener(a -> setStatus(selected, Finding.Status.FALSE_POSITIVE));
        menu.add(markFalsePositive);

        JMenuItem markNew = new JMenuItem("Mark New");
        markNew.addActionListener(a -> setStatus(selected, Finding.Status.NEW));
        menu.add(markNew);

        menu.addSeparator();

        JMenuItem copy = new JMenuItem("Copy URL" + (selected.size() > 1 ? "s" : ""));
        copy.addActionListener(a -> {
            StringBuilder sb = new StringBuilder();
            for (Finding f : selected) {
                if (sb.length() > 0) sb.append('\n');
                sb.append(f.issue().baseUrl());
            }
            Toolkit.getDefaultToolkit().getSystemClipboard()
                    .setContents(new StringSelection(sb.toString()), null);
        });
        menu.add(copy);

        menu.show(table, x, y);
    }

    /** Sends each selected finding's first evidence request to Burp's Repeater tool. */
    private void sendToRepeater(List<Finding> selected) {
        int sent = 0;
        for (Finding f : selected) {
            List<HttpRequestResponse> evidence = f.issue().requestResponses();
            if (evidence == null || evidence.isEmpty() || evidence.get(0).request() == null) {
                continue;
            }
            HttpRequest req = evidence.get(0).request();
            String caption = shortCaption(f.issue().name());
            api.repeater().sendToRepeater(req, caption);
            sent++;
        }
        if (sent == 0) {
            JOptionPane.showMessageDialog(rootPanel,
                    "None of the selected finding(s) have request/response evidence to send "
                            + "(e.g. the Collaborator-only SSRF check proves itself out-of-band, with no "
                            + "single HTTP request/response to replay).",
                    "LawCyBug.pro", JOptionPane.INFORMATION_MESSAGE);
        } else {
            api.logging().logToOutput("[LawCyBug.pro] Sent " + sent + " request(s) to Repeater.");
        }
    }

    private String shortCaption(String issueName) {
        String name = issueName == null ? "Finding" : issueName.replace("[LawCyBug.pro] ", "");
        return name.length() > 30 ? name.substring(0, 30) : name;
    }

    private void setStatus(List<Finding> selected, Finding.Status status) {
        for (Finding f : selected) {
            f.setStatus(status);
        }
        tableModel.fireTableDataChanged();
    }

    /** Renders FALSE_POSITIVE rows dimmed/italic and REVIEWED rows in a muted accent, so triage state is visible at a glance. */
    private final class StatusAwareRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
                                                         boolean hasFocus, int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            int modelRow = table.convertRowIndexToModel(row);
            Finding f = tableModel.getFinding(modelRow);
            setBackground(isSelected ? ROW_HIGH : PANEL_BG);
            if (f.status() == Finding.Status.FALSE_POSITIVE) {
                setForeground(new Color(0x88, 0x88, 0x88));
                setFont(getFont().deriveFont(Font.ITALIC));
            } else if (f.status() == Finding.Status.REVIEWED) {
                setForeground(BRAND_ACCENT);
                setFont(getFont().deriveFont(Font.PLAIN));
            } else {
                setForeground(BRAND_FG);
                setFont(getFont().deriveFont(Font.PLAIN));
            }
            return c;
        }
    }

    /**
     * Builds the request/response evidence panel shown below the findings table.
     * Uses Burp's own read-only HTTP editors so any markers a detector attached
     * via IssueFactory.withResponseHighlight/withResponseBodyHighlight render
     * exactly like they do in Burp's native Issue view.
     */
    private JPanel buildEvidenceViewerPanel() {
        requestEditor  = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        responseEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);

        JPanel viewerPanel = new JPanel(new BorderLayout());
        viewerPanel.setBackground(PANEL_BG);

        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        toolbar.setBackground(BRAND_BG);
        JLabel evidenceLabel = new JLabel("Evidence:");
        evidenceLabel.setForeground(BRAND_FG);
        evidenceSelector = new JComboBox<>();
        evidenceSelector.addActionListener(e -> displaySelectedEvidence());
        toolbar.add(evidenceLabel);
        toolbar.add(evidenceSelector);
        viewerPanel.add(toolbar, BorderLayout.NORTH);

        JSplitPane reqRespSplit = new JSplitPane(
                JSplitPane.HORIZONTAL_SPLIT,
                titled("Request", requestEditor.uiComponent()),
                titled("Response", responseEditor.uiComponent()));
        reqRespSplit.setResizeWeight(0.5);
        reqRespSplit.setBackground(PANEL_BG);

        JLabel emptyLabel = new JLabel("Select a finding above to view its request/response.", SwingConstants.CENTER);
        emptyLabel.setForeground(BRAND_FG);

        evidenceCardPanel = new JPanel(new CardLayout());
        evidenceCardPanel.setBackground(PANEL_BG);
        evidenceCardPanel.add(emptyLabel, CARD_EMPTY);
        evidenceCardPanel.add(reqRespSplit, CARD_VIEWER);
        viewerPanel.add(evidenceCardPanel, BorderLayout.CENTER);

        showEvidence(List.of());
        return viewerPanel;
    }

    private JPanel titled(String title, Component comp) {
        JPanel p = new JPanel(new BorderLayout());
        p.setBackground(PANEL_BG);
        p.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(new Color(0x33, 0x33, 0x55)), title));
        p.add(comp, BorderLayout.CENTER);
        return p;
    }

    /** Populates the evidence selector for a finding's evidence list and shows the first item. */
    private void showEvidence(List<HttpRequestResponse> evidence) {
        currentEvidence = evidence;
        CardLayout cl = (CardLayout) evidenceCardPanel.getLayout();

        if (evidence == null || evidence.isEmpty()) {
            evidenceSelector.removeAllItems();
            evidenceSelector.setEnabled(false);
            cl.show(evidenceCardPanel, CARD_EMPTY);
            return;
        }

        evidenceSelector.removeAllItems();
        for (int i = 0; i < evidence.size(); i++) {
            evidenceSelector.addItem("Evidence " + (i + 1) + " of " + evidence.size());
        }
        evidenceSelector.setEnabled(evidence.size() > 1);
        evidenceSelector.setSelectedIndex(0);
        cl.show(evidenceCardPanel, CARD_VIEWER);
        displaySelectedEvidence();
    }

    private void displaySelectedEvidence() {
        if (currentEvidence.isEmpty()) return;
        int idx = evidenceSelector.getSelectedIndex();
        if (idx < 0 || idx >= currentEvidence.size()) idx = 0;
        HttpRequestResponse rr = currentEvidence.get(idx);
        if (rr.request() != null) {
            requestEditor.setRequest(rr.request());
        }
        if (rr.response() != null) {
            responseEditor.setResponse(rr.response());
        }
    }

    // ── Settings tab ──────────────────────────────────────────────────────────
    private JScrollPane buildSettingsPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBackground(PANEL_BG);
        panel.setBorder(new EmptyBorder(12, 12, 12, 12));

        // Global options
        panel.add(sectionLabel("Global Options"));

        JComboBox<ScanSettings.Intensity> intensityBox = new JComboBox<>(ScanSettings.Intensity.values());
        intensityBox.setSelectedItem(settings.getIntensity());
        intensityBox.addActionListener(e -> settings.setIntensity((ScanSettings.Intensity) intensityBox.getSelectedItem()));
        panel.add(labeledRow("Scan intensity:", intensityBox));

        JCheckBox collabCb = new JCheckBox("Enable Collaborator (OOB checks - requires Burp Pro)");
        collabCb.setSelected(settings.isCollaboratorEnabled());
        collabCb.setForeground(BRAND_FG);
        collabCb.setBackground(PANEL_BG);
        collabCb.addActionListener(e -> settings.setCollaboratorEnabled(collabCb.isSelected()));
        panel.add(collabCb);

        JCheckBox scopeCb = new JCheckBox("Only scan URLs within Burp's defined scope");
        scopeCb.setSelected(settings.isOnlyScanInScope());
        scopeCb.setForeground(BRAND_FG);
        scopeCb.setBackground(PANEL_BG);
        scopeCb.addActionListener(e -> settings.setOnlyScanInScope(scopeCb.isSelected()));
        panel.add(scopeCb);

        JSpinner delaySpinner = new JSpinner(new SpinnerNumberModel(settings.getTimeBasedDelaySeconds(), 2, 30, 1));
        delaySpinner.addChangeListener(e -> settings.setTimeBasedDelaySeconds(((Number) delaySpinner.getValue()).longValue()));
        panel.add(labeledRow("Time-based delay (seconds):", delaySpinner));

        JSpinner repeatsSpinner = new JSpinner(new SpinnerNumberModel(settings.getTimeBasedRequestRepeats(), 1, 5, 1));
        repeatsSpinner.addChangeListener(e -> settings.setTimeBasedRequestRepeats(((Number) repeatsSpinner.getValue()).intValue()));
        panel.add(labeledRow("Time-based repeat measurements:", repeatsSpinner));

        // ── Authorization testing (IDOR/BOLA confirmation + race conditions) ──
        panel.add(Box.createVerticalStrut(16));
        panel.add(sectionLabel("Authorization Testing"));

        JLabel idorHint = new JLabel("<html><div style='width:520px;'>To CONFIRM (not just flag) IDOR/BOLA, "
                + "log in as a second, lower-privileged account and paste its session credential below. "
                + "Leave blank to disable IDOR confirmation -- it will skip silently with no false positives.</div></html>");
        idorHint.setForeground(BRAND_FG);
        idorHint.setBorder(new EmptyBorder(2, 0, 6, 0));
        panel.add(idorHint);

        JTextField secondaryHeaderNameField = new JTextField(settings.getSecondarySessionHeaderName(), 14);
        secondaryHeaderNameField.addActionListener(e -> settings.setSecondarySessionHeaderName(secondaryHeaderNameField.getText()));
        secondaryHeaderNameField.addFocusListener(new java.awt.event.FocusAdapter() {
            @Override public void focusLost(java.awt.event.FocusEvent e) {
                settings.setSecondarySessionHeaderName(secondaryHeaderNameField.getText());
            }
        });
        panel.add(labeledRow("Secondary identity - header name:", secondaryHeaderNameField));

        JTextField secondaryHeaderValueField = new JTextField(settings.getSecondarySessionHeaderValue(), 40);
        secondaryHeaderValueField.setToolTipText("e.g. \"Bearer eyJ...\" for Authorization, or \"session=abc123\" for Cookie");
        secondaryHeaderValueField.addActionListener(e -> settings.setSecondarySessionHeaderValue(secondaryHeaderValueField.getText()));
        secondaryHeaderValueField.addFocusListener(new java.awt.event.FocusAdapter() {
            @Override public void focusLost(java.awt.event.FocusEvent e) {
                settings.setSecondarySessionHeaderValue(secondaryHeaderValueField.getText());
            }
        });
        panel.add(labeledRow("Secondary identity - header value:", secondaryHeaderValueField));

        JSpinner raceConcurrencySpinner = new JSpinner(new SpinnerNumberModel(settings.getRaceConditionConcurrency(), 2, 100, 1));
        raceConcurrencySpinner.setToolTipText("Number of truly concurrent requests fired at single-use/limited-resource endpoints to detect race conditions.");
        raceConcurrencySpinner.addChangeListener(e -> settings.setRaceConditionConcurrency(((Number) raceConcurrencySpinner.getValue()).intValue()));
        panel.add(labeledRow("Race condition concurrency (requests):", raceConcurrencySpinner));

        // ── Safe Mode / Chain Engine (governs every mutating multi-step detector) ──
        panel.add(Box.createVerticalStrut(16));
        panel.add(sectionLabel("⚠ Chain Engine Safety (BOLA/ATO/Business-Logic chains)"));

        JLabel safeModeHint = new JLabel("<html><div style='width:520px;'>"
                + "Privilege-escalation, business-logic, and account-takeover chains can send real "
                + "state-MUTATING requests (apply a coupon, change a role, submit an order). "
                + "<b>Safe Mode is ON by default</b> and blocks every step a detector marks as "
                + "mutating. Only disable it for an explicitly authorized engagement where you accept "
                + "that real state changes may occur on the target.</div></html>");
        safeModeHint.setForeground(BRAND_FG);
        safeModeHint.setBorder(new EmptyBorder(2, 0, 6, 0));
        panel.add(safeModeHint);

        JCheckBox safeModeCb = new JCheckBox("Safe Mode enabled (block mutating chain steps)");
        safeModeCb.setSelected(settings.isSafeModeEnabled());
        safeModeCb.setForeground(BRAND_FG);
        safeModeCb.setBackground(PANEL_BG);
        safeModeCb.setFont(safeModeCb.getFont().deriveFont(java.awt.Font.BOLD));
        safeModeCb.addActionListener(e -> {
            if (!safeModeCb.isSelected()) {
                int confirm = JOptionPane.showConfirmDialog(panel,
                        "Disabling Safe Mode allows chain detectors to send real state-mutating requests "
                                + "(coupon application, role changes, order submission, etc.) against the target.\n\n"
                                + "Only proceed if you are explicitly authorized to do so on this target.\n\n"
                                + "Disable Safe Mode?",
                        "Confirm: Disable Safe Mode", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
                if (confirm != JOptionPane.YES_OPTION) {
                    safeModeCb.setSelected(true);
                    return;
                }
            }
            settings.setSafeModeEnabled(safeModeCb.isSelected());
        });
        panel.add(safeModeCb);

        JSpinner maxChainSpinner = new JSpinner(new SpinnerNumberModel(settings.getMaxRequestsPerChain(), 1, 50, 1));
        maxChainSpinner.setToolTipText("Hard ceiling on extra requests a single chain detector may send per base request.");
        maxChainSpinner.addChangeListener(e -> settings.setMaxRequestsPerChain(((Number) maxChainSpinner.getValue()).intValue()));
        panel.add(labeledRow("Max requests per chain:", maxChainSpinner));

        JSpinner chainDelaySpinner = new JSpinner(new SpinnerNumberModel(settings.getChainRequestDelayMillis(), 0, 5000, 50));
        chainDelaySpinner.setToolTipText("Minimum delay between consecutive chain requests, to avoid hammering the target.");
        chainDelaySpinner.addChangeListener(e -> settings.setChainRequestDelayMillis(((Number) chainDelaySpinner.getValue()).longValue()));
        panel.add(labeledRow("Chain request delay (ms):", chainDelaySpinner));

        // Per-detector toggles
        panel.add(Box.createVerticalStrut(16));
        panel.add(sectionLabel("Passive Detectors"));
        for (var d : engine.passiveDetectors()) {
            panel.add(detectorToggle(d.id(), d.displayName(), d.description()));
        }
        panel.add(Box.createVerticalStrut(8));
        panel.add(sectionLabel("Active Detectors"));
        for (var d : engine.activeDetectors()) {
            panel.add(detectorToggle(d.id(), d.displayName(), d.description()));
        }

        JScrollPane scroll = new JScrollPane(panel);
        scroll.setBackground(PANEL_BG);
        scroll.getVerticalScrollBar().setUnitIncrement(16);
        return scroll;
    }

    // ── Rules tab ─────────────────────────────────────────────────────────────
    // ── Identities panel: configure Victim/Attacker/Anonymous credential sets
    //    consumed by the cross-identity BOLA/ATO/business-logic chain engine.
    private JPanel buildIdentitiesPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBackground(PANEL_BG);
        panel.setBorder(new EmptyBorder(10, 10, 10, 10));

        JLabel intro = new JLabel(
                "<html>Configure named sessions so active detectors (BOLA/IDOR cross-identity replay, "
                        + "ATO chains, business-logic chains) can automatically swap credentials and compare "
                        + "results. Define at least one <b>VICTIM</b> and one <b>ATTACKER</b> identity to "
                        + "enable cross-identity testing.</html>");
        intro.setForeground(BRAND_FG);
        intro.setBorder(new EmptyBorder(0, 0, 10, 0));
        panel.add(intro, BorderLayout.NORTH);

        String[] columns = {"Name", "Role", "Header Name", "Header Value", "Cookie Header Value"};
        javax.swing.table.DefaultTableModel model = new javax.swing.table.DefaultTableModel(columns, 0);
        JTable table = new JTable(model);
        table.setRowHeight(22);
        table.setBackground(PANEL_BG);
        table.setForeground(BRAND_FG);
        table.getTableHeader().setReorderingAllowed(false);

        JComboBox<String> roleCombo = new JComboBox<>(
                new String[]{"VICTIM", "ATTACKER", "ANONYMOUS", "ADMIN", "CUSTOM"});
        table.getColumnModel().getColumn(1).setCellEditor(new DefaultCellEditor(roleCombo));

        JButton addRow = new JButton("+ Add Identity");
        JButton removeRow = new JButton("− Remove Selected");
        JButton apply = new JButton("Apply to Engine");
        apply.setBackground(BRAND_ACCENT);

        addRow.addActionListener(e -> model.addRow(new Object[]{"New Identity", "VICTIM", "Authorization", "", ""}));
        removeRow.addActionListener(e -> {
            int row = table.getSelectedRow();
            if (row >= 0) model.removeRow(row);
        });
        apply.addActionListener(e -> {
            identityRegistry.all().clear();
            for (int i = 0; i < model.getRowCount(); i++) {
                String name = String.valueOf(model.getValueAt(i, 0));
                String roleStr = String.valueOf(model.getValueAt(i, 1));
                String headerName = String.valueOf(model.getValueAt(i, 2));
                String headerValue = String.valueOf(model.getValueAt(i, 3));
                String cookie = String.valueOf(model.getValueAt(i, 4));
                if (name.isBlank()) continue;
                SessionIdentity.Role role;
                try {
                    role = SessionIdentity.Role.valueOf(roleStr);
                } catch (Exception ex) {
                    role = SessionIdentity.Role.CUSTOM;
                }
                SessionIdentity identity = new SessionIdentity(name, role);
                if (!headerName.isBlank() && !headerValue.isBlank()) {
                    identity.withHeader(headerName, headerValue);
                }
                if (!cookie.isBlank()) {
                    identity.withCookie(cookie);
                }
                identityRegistry.register(identity);
            }
            JOptionPane.showMessageDialog(panel,
                    identityRegistry.all().size() + " identity(ies) applied. "
                            + (identityRegistry.hasMultiUserSetup()
                            ? "Cross-identity testing is now ACTIVE."
                            : "Define at least one VICTIM and one ATTACKER identity to activate cross-identity testing."),
                    "LawCyBug.pro", JOptionPane.INFORMATION_MESSAGE);
        });

        JPanel buttonRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        buttonRow.setBackground(PANEL_BG);
        buttonRow.add(addRow);
        buttonRow.add(removeRow);
        buttonRow.add(apply);

        panel.add(new JScrollPane(table), BorderLayout.CENTER);
        panel.add(buttonRow, BorderLayout.SOUTH);
        return panel;
    }

    private JPanel buildRulesPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBackground(PANEL_BG);
        panel.setBorder(new EmptyBorder(12, 12, 12, 12));

        JLabel heading = new JLabel(rulesHeadingText());
        heading.setForeground(BRAND_ACCENT);
        heading.setFont(new Font("SansSerif", Font.BOLD, 14));
        panel.add(heading, BorderLayout.NORTH);

        JTextArea jsonEditor = new JTextArea(20, 60);
        jsonEditor.setBackground(new Color(0x12, 0x12, 0x22));
        jsonEditor.setForeground(BRAND_ACCENT);
        jsonEditor.setCaretColor(BRAND_FG);
        jsonEditor.setFont(new Font("Monospaced", Font.PLAIN, 12));
        jsonEditor.setText(DEFAULT_RULE_EXAMPLE);
        panel.add(new JScrollPane(jsonEditor), BorderLayout.CENTER);

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT));
        buttons.setBackground(PANEL_BG);

        JButton loadTextBtn = new JButton("➕ Load from editor");
        loadTextBtn.setToolTipText("Adds these rules on top of what's already loaded (bundled rules are untouched)");
        loadTextBtn.addActionListener(e -> {
            try {
                int before = ruleEngine.ruleCount();
                ruleEngine.loadFromJson(jsonEditor.getText());
                int added = ruleEngine.ruleCount() - before;
                heading.setText(rulesHeadingText());
                JOptionPane.showMessageDialog(panel,
                        "Added " + added + " rule(s) from the editor.", "LawCyBug.pro", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(panel, "Parse error: " + ex.getMessage(), "LawCyBug.pro", JOptionPane.ERROR_MESSAGE);
            }
        });
        styleButton(loadTextBtn);

        JButton loadFileBtn = new JButton("➕ Load from .json file");
        loadFileBtn.setToolTipText("Adds rules from a file on top of what's already loaded (bundled rules are untouched)");
        loadFileBtn.addActionListener(e -> {
            JFileChooser fc = new JFileChooser();
            fc.setFileFilter(new FileNameExtensionFilter("JSON files", "json"));
            if (fc.showOpenDialog(panel) == JFileChooser.APPROVE_OPTION) {
                try {
                    int before = ruleEngine.ruleCount();
                    ruleEngine.loadFromFile(fc.getSelectedFile().toPath());
                    int added = ruleEngine.ruleCount() - before;
                    heading.setText(rulesHeadingText());
                    JOptionPane.showMessageDialog(panel,
                            "Added " + added + " rule(s) from " + fc.getSelectedFile().getName(),
                            "LawCyBug.pro", JOptionPane.INFORMATION_MESSAGE);
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(panel, "Load error: " + ex.getMessage(), "LawCyBug.pro", JOptionPane.ERROR_MESSAGE);
                }
            }
        });
        styleButton(loadFileBtn);

        JButton reloadBundledBtn = new JButton("↻ Reload bundled rules");
        reloadBundledBtn.setToolTipText("Re-reads the rule packs shipped inside this extension's jar (useful after rebuilding with updated rule files)");
        reloadBundledBtn.addActionListener(e -> {
            ruleEngine.clearBundledRules();
            CustomRuleEngine.BundleLoadResult result = ruleEngine.loadBundledRules();
            heading.setText(rulesHeadingText());
            if (result.allOk()) {
                JOptionPane.showMessageDialog(panel,
                        "Reloaded " + result.filesLoaded() + " bundled pack(s), " + result.rulesLoaded() + " rule(s) total.",
                        "LawCyBug.pro", JOptionPane.INFORMATION_MESSAGE);
            } else {
                JOptionPane.showMessageDialog(panel,
                        "Loaded " + result.filesLoaded() + "/" + result.filesAttempted() + " bundled pack(s).\n"
                                + "Failures:\n" + String.join("\n", result.errors()),
                        "LawCyBug.pro", JOptionPane.WARNING_MESSAGE);
            }
        });
        styleButton(reloadBundledBtn);

        JButton clearManualBtn = new JButton("Clear manual rules");
        clearManualBtn.setToolTipText("Removes only rules you added via the editor/file buttons above — bundled rules stay loaded");
        clearManualBtn.addActionListener(e -> {
            ruleEngine.clearManualRules();
            heading.setText(rulesHeadingText());
        });
        styleButton(clearManualBtn);

        JButton clearAllBtn = new JButton("Clear ALL rules");
        clearAllBtn.setToolTipText("Removes everything, including the bundled rule packs — use Reload bundled rules to bring them back");
        clearAllBtn.addActionListener(e -> {
            ruleEngine.clearRules();
            heading.setText(rulesHeadingText());
        });
        styleButton(clearAllBtn);

        buttons.add(loadTextBtn);
        buttons.add(loadFileBtn);
        buttons.add(reloadBundledBtn);
        buttons.add(clearManualBtn);
        buttons.add(clearAllBtn);
        panel.add(buttons, BorderLayout.SOUTH);

        return panel;
    }

    private String rulesHeadingText() {
        return "Custom JSON Rules  (" + ruleEngine.bundledRuleCount() + " bundled + "
                + ruleEngine.manualRuleCount() + " manual = " + ruleEngine.ruleCount() + " total)";
    }

    // ── Helpers ───────────────────────────────────────────────────────────────
    private JComponent detectorToggle(String id, String name, String tooltip) {
        JCheckBox cb = new JCheckBox(name, settings.isDetectorEnabled(id));
        cb.setToolTipText(tooltip);
        cb.setForeground(BRAND_FG);
        cb.setBackground(PANEL_BG);
        cb.addActionListener(e -> settings.setDetectorEnabled(id, cb.isSelected()));
        return cb;
    }

    private JPanel labeledRow(String label, JComponent comp) {
        JPanel row = new JPanel(new FlowLayout(FlowLayout.LEFT));
        row.setBackground(PANEL_BG);
        JLabel lbl = new JLabel(label);
        lbl.setForeground(BRAND_FG);
        row.add(lbl);
        row.add(comp);
        return row;
    }

    private JLabel sectionLabel(String text) {
        JLabel lbl = new JLabel(text);
        lbl.setForeground(BRAND_ACCENT);
        lbl.setFont(new Font("SansSerif", Font.BOLD, 13));
        lbl.setBorder(new EmptyBorder(8, 0, 4, 0));
        return lbl;
    }

    private JLabel statLabel(String text, Color color) {
        JLabel l = new JLabel(text);
        l.setForeground(color);
        l.setFont(new Font("SansSerif", Font.BOLD, 13));
        return l;
    }

    private void styleButton(JButton btn) {
        btn.setBackground(BRAND_ACCENT);
        btn.setForeground(Color.BLACK);
        btn.setFont(new Font("SansSerif", Font.BOLD, 12));
        btn.setFocusPainted(false);
    }

    private static final String DEFAULT_RULE_EXAMPLE = """
            [
              {
                "name": "Internal IP Disclosure",
                "type": "passive",
                "severity": "medium",
                "confidence": "firm",
                "description": "An RFC1918 internal IP address was found in the HTTP response body.",
                "remediation": "Remove internal IP addresses from API responses and error messages.",
                "conditions": [
                  {
                    "target": "response_body",
                    "pattern": "\\\\b(10\\\\.[0-9]{1,3}\\\\.[0-9]{1,3}\\\\.[0-9]{1,3}|172\\\\.(1[6-9]|2[0-9]|3[01])\\\\.[0-9]{1,3}\\\\.[0-9]{1,3}|192\\\\.168\\\\.[0-9]{1,3}\\\\.[0-9]{1,3})\\\\b"
                  }
                ]
              }
            ]
            """;

    // ── Table model ───────────────────────────────────────────────────────────
    private static final class FindingsTableModel extends AbstractTableModel {
        private static final String[] COLS = {"Time", "Severity", "Detector", "URL", "Issue Name", "Status"};
        private final List<Finding> data = new ArrayList<>();

        void addFinding(Finding f) {
            data.add(f);
            fireTableRowsInserted(data.size() - 1, data.size() - 1);
        }

        void clear() {
            int n = data.size();
            if (n == 0) return;
            data.clear();
            fireTableRowsDeleted(0, n - 1);
        }

        Finding getFinding(int row) {
            return data.get(row);
        }

        @Override public int getRowCount()    { return data.size(); }
        @Override public int getColumnCount() { return COLS.length; }
        @Override public String getColumnName(int c) { return COLS[c]; }

        @Override
        public Object getValueAt(int row, int col) {
            Finding f = data.get(row);
            return switch (col) {
                case 0 -> f.formattedTime();
                case 1 -> f.issue().severity().name();
                case 2 -> f.detectorId();
                case 3 -> f.issue().baseUrl();
                case 4 -> f.issue().name();
                case 5 -> f.status().label;
                default -> "";
            };
        }
    }
}
