# -*- coding: utf-8 -*-
#
# Burp Suite Extension - Auto SQLi All Body Params Checker UI v7
# Runtime: Jython 2.7.x
#
# v6 behavior:
# - For each Proxy request, parse all body params
# - Replace ALL body params in the request with payload: '
# - Send ONE mutated request
# - Show original request, mutated request, response preview
# - Detect SQL error in response
#
# Note:
# - Best for quick endpoint-level SQL error check
# - If FOUND, manually retest field-by-field to identify exact vulnerable param

from burp import IBurpExtender
from burp import IHttpListener
from burp import IScanIssue
from burp import ITab

from java.awt import BorderLayout
from java.awt import FlowLayout
from javax.swing import JPanel
from javax.swing import JScrollPane
from javax.swing import JTextArea
from javax.swing import JButton
from javax.swing import JLabel
from javax.swing import JCheckBox
from javax.swing import JTable
from javax.swing import JSplitPane
from javax.swing import JTextField
from javax.swing import SwingUtilities
from javax.swing.table import DefaultTableModel
from javax.swing.event import ListSelectionListener

from java.text import SimpleDateFormat
from java.util import Date
from java.util.concurrent.atomic import AtomicInteger
from java.lang import Runnable
from java.lang import Thread

import re
import json


class BurpExtender(IBurpExtender, IHttpListener, ITab):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        callbacks.setExtensionName("Auto SQLi All Body Params - UI v7")

        self._payload = "'"
        self._payload_confirm = "''"
        self._marker_header = "X-Auto-SQLi-Check: 1"

        self._enabled = True
        self._request_counter = AtomicInteger(0)
        self._row_counter = AtomicInteger(0)

        self._details = {}

        self._sql_error_regex = re.compile(
            r"(?i)("
            r"System\.Data\.SqlClient\.SqlException|"
            r"Microsoft\.Data\.SqlClient\.SqlException|"
            r"SqlException|"
            r"SQL Server|"
            r"SQL Server Native Client|"
            r"ODBC SQL Server Driver|"

            r"Incorrect syntax near|"
            r"Unclosed quotation mark|"
            r"Unclosed quotation mark after the character string|"
            r"quoted string not properly terminated|"
            r"Conversion failed when converting|"
            r"Error converting data type|"
            r"The multi-part identifier .* could not be bound|"
            r"Invalid column name|"
            r"Invalid object name|"
            r"Must declare the scalar variable|"
            r"An unexpected error occurred.|"

            r"SQL syntax|"
            r"syntax error|"
            r"unterminated quoted string|"
            r"Data type mismatch|"

            r"MySQL server version|"
            r"mysql_fetch|"
            r"MariaDB|"
            r"You have an error in your SQL syntax|"

            r"PostgreSQL.*ERROR|"
            r"pg_query\(|"
            r"syntax error at or near|"
            r"unterminated quoted string at or near|"

            r"ORA-[0-9]{5}|"
            r"Oracle error|"

            r"SQLiteException|"
            r"SQLite/JDBCDriver|"
            r"near \".*\": syntax error"
            r")"
        )

        self._build_ui()

        callbacks.customizeUiComponent(self._main_panel)
        callbacks.addSuiteTab(self)
        callbacks.registerHttpListener(self)

        self._log("[+] Loaded Auto SQLi All Body Params UI v7")
        self._log("[+] Mode: test payload ' first; if suspicious generic error appears, retest with ''")
        self._log("[+] Payloads: ' then ''")

    # =========================
    # UI
    # =========================

    def getTabCaption(self):
        return "Auto SQLi"

    def getUiComponent(self):
        return self._main_panel

    def _build_ui(self):
        self._main_panel = JPanel(BorderLayout())

        top_panel = JPanel(FlowLayout(FlowLayout.LEFT))

        self._status_label = JLabel("Status: Enabled")

        self._enabled_checkbox = JCheckBox("Enable testing", True)
        self._enabled_checkbox.addActionListener(self._toggle_enabled)

        self._scope_checkbox = JCheckBox("Only in-scope", True)

        self._timeout_label = JLabel("Timeout ms:")
        self._timeout_field = JTextField("10000", 7)

        clear_log_button = JButton("Clear Log")
        clear_log_button.addActionListener(self._clear_log)

        clear_results_button = JButton("Clear Results")
        clear_results_button.addActionListener(self._clear_results)

        top_panel.add(self._status_label)
        top_panel.add(self._enabled_checkbox)
        top_panel.add(self._scope_checkbox)
        top_panel.add(self._timeout_label)
        top_panel.add(self._timeout_field)
        top_panel.add(clear_log_button)
        top_panel.add(clear_results_button)

        columns = [
            "Row ID",
            "Time",
            "Req ID",
            "Method",
            "URL",
            "Fields Count",
            "Payload",
            "HTTP Status",
            "Resp Length",
            "Result",
            "Evidence / Response Preview"
        ]

        self._table_model = DefaultTableModel(columns, 0)
        self._results_table = JTable(self._table_model)
        self._results_table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF)
        self._results_table.getSelectionModel().addListSelectionListener(RowSelectionListener(self))

        table_scroll = JScrollPane(self._results_table)

        self._detail_area = JTextArea()
        self._detail_area.setEditable(False)
        self._detail_area.setLineWrap(False)
        self._detail_area.setWrapStyleWord(False)
        detail_scroll = JScrollPane(self._detail_area)

        self._log_area = JTextArea()
        self._log_area.setEditable(False)
        self._log_area.setLineWrap(True)
        self._log_area.setWrapStyleWord(True)
        log_scroll = JScrollPane(self._log_area)

        lower_split = JSplitPane(JSplitPane.VERTICAL_SPLIT, detail_scroll, log_scroll)
        lower_split.setResizeWeight(0.65)

        main_split = JSplitPane(JSplitPane.VERTICAL_SPLIT, table_scroll, lower_split)
        main_split.setResizeWeight(0.35)

        self._main_panel.add(top_panel, BorderLayout.NORTH)
        self._main_panel.add(main_split, BorderLayout.CENTER)

    def _toggle_enabled(self, event):
        self._enabled = self._enabled_checkbox.isSelected()
        if self._enabled:
            self._status_label.setText("Status: Enabled")
            self._log("[+] Testing enabled")
        else:
            self._status_label.setText("Status: Disabled")
            self._log("[-] Testing disabled")

    def _clear_log(self, event):
        self._log_area.setText("")

    def _clear_results(self, event):
        def clear():
            self._table_model.setRowCount(0)
            self._detail_area.setText("")
            self._details.clear()

        SwingUtilities.invokeLater(clear)
        self._log("[+] Results cleared")

    def _get_timeout_ms(self):
        try:
            value = int(self._timeout_field.getText().strip())
            if value < 1000:
                return 1000
            return value
        except:
            return 10000

    def _log(self, msg):
        try:
            timestamp = SimpleDateFormat("HH:mm:ss").format(Date())
            line = u"[%s] %s\n" % (
                self._safe_short(timestamp, 50),
                self._safe_short(msg, 5000)
            )

            def append():
                self._log_area.append(line)
                self._log_area.setCaretPosition(self._log_area.getDocument().getLength())

            SwingUtilities.invokeLater(append)

            try:
                print(line.encode("utf-8"))
            except:
                print("[log-unicode-error]")

        except Exception as e:
            try:
                print("[!] Log error: %s" % str(e))
            except:
                pass

    # =========================
    # HTTP Listener
    # =========================

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        try:
            if not self._enabled:
                return

            if not messageIsRequest:
                return

            if toolFlag != self._callbacks.TOOL_PROXY:
                return

            request = messageInfo.getRequest()
            request_info = self._helpers.analyzeRequest(messageInfo)

            url = request_info.getUrl()
            method = request_info.getMethod()

            if self._has_marker_header(request_info):
                return

            if self._scope_checkbox.isSelected() and not self._callbacks.isInScope(url):
                self._log("[SKIP] Out of scope: %s %s" % (
                    self._safe_short(method, 50),
                    self._safe_short(url, 500)
                ))
                return

            body_offset = request_info.getBodyOffset()
            if body_offset >= len(request):
                self._log("[SKIP] No body: %s %s" % (
                    self._safe_short(method, 50),
                    self._safe_short(url, 500)
                ))
                return

            params = request_info.getParameters()
            if params is None or len(params) == 0:
                self._log("[SKIP] No params parsed by Burp: %s %s" % (
                    self._safe_short(method, 50),
                    self._safe_short(url, 500)
                ))
                return

            body_params = []
            for p in params:
                if self._is_body_param(p):
                    body_params.append(p)

            if len(body_params) == 0:
                self._log("[SKIP] No body params: %s %s" % (
                    self._safe_short(method, 50),
                    self._safe_short(url, 500)
                ))
                return

            req_id = self._request_counter.incrementAndGet()

            service = messageInfo.getHttpService()
            base_request = request[:]
            original_request_text = self._helpers.bytesToString(base_request)

            param_snapshots = []

            for p in body_params:
                param_snapshots.append({
                    "name": p.getName(),
                    "value": p.getValue(),
                    "type": p.getType(),
                    "type_name": self._param_type_name(p.getType())
                })

            fields_summary = self._build_fields_summary(param_snapshots)

            self._log("")
            self._log("[REQ-%s] %s %s" % (
                self._safe_short(req_id, 50),
                self._safe_short(method, 50),
                self._safe_short(url, 800)
            ))
            self._log("[REQ-%s] Parsed body params=%s" % (
                self._safe_short(req_id, 50),
                self._safe_short(len(param_snapshots), 50)
            ))
            self._log("[REQ-%s] Replacing ALL parsed body params with payload: '" % (
                self._safe_short(req_id, 50)
            ))

            for line in fields_summary.split("\n"):
                self._log("[REQ-%s] %s" % (
                    self._safe_short(req_id, 50),
                    self._safe_short(line, 1000)
                ))

            row_id = self.create_row(
                req_id=req_id,
                method=method,
                url=url,
                fields_count=len(param_snapshots),
                fields_summary=fields_summary,
                original_request_text=original_request_text
            )

            worker = AllParamsTestWorker(
                self,
                req_id,
                service,
                base_request,
                original_request_text,
                method,
                url,
                row_id,
                param_snapshots,
                fields_summary
            )

            Thread(worker).start()

        except Exception as e:
            self._log("[!] Error in processHttpMessage: %s" % self._safe_short(e, 1000))

    def _has_marker_header(self, request_info):
        headers = list(request_info.getHeaders())
        for h in headers:
            h = self._to_unicode(h)
            if h.lower().startswith(u"x-auto-sqli-check:"):
                return True
        return False

    def _is_body_param(self, p):
        t = p.getType()

        # Burp legacy constants:
        # PARAM_URL            = 0
        # PARAM_BODY           = 1
        # PARAM_COOKIE         = 2
        # PARAM_XML            = 3
        # PARAM_XML_ATTR       = 4
        # PARAM_MULTIPART_ATTR = 5
        # PARAM_JSON           = 6
        return t in [1, 3, 4, 5, 6]

    def _param_type_name(self, param_type):
        mapping = {
            0: "URL",
            1: "BODY",
            2: "COOKIE",
            3: "XML",
            4: "XML_ATTR",
            5: "MULTIPART_ATTR",
            6: "JSON"
        }

        if param_type in mapping:
            return mapping[param_type]

        return str(param_type)

    def _build_fields_summary(self, param_snapshots):
        lines = []
        idx = 1

        for p in param_snapshots:
            lines.append(u"%03d. [%s] %s = %s" % (
                idx,
                self._safe_short(p["type_name"], 50),
                self._safe_short(p["name"], 300),
                self._safe_short(p["value"], 500)
            ))
            idx += 1

        return u"\n".join(lines)

    # =========================
    # Row handling
    # =========================

    def create_row(self, req_id, method, url, fields_count, fields_summary, original_request_text):
        row_id = self._row_counter.incrementAndGet()
        timestamp = SimpleDateFormat("HH:mm:ss").format(Date())

        row = [
            self._safe_short(row_id, 50),
            self._safe_short(timestamp, 50),
            self._safe_short(req_id, 50),
            self._safe_short(method, 50),
            self._safe_short(url, 500),
            self._safe_short(fields_count, 50),
            self._payload,
            "",
            "",
            "PENDING",
            "Row created. Waiting mutation..."
        ]

        detail = self._build_detail(
            result="PENDING",
            evidence="Row created. Waiting mutation...",
            req_id=req_id,
            method=method,
            url=url,
            fields_count=fields_count,
            fields_summary=fields_summary,
            original_request_text=original_request_text,
            mutated_request_text="",
            status_code="",
            resp_len="",
            response_preview=""
        )

        self._details[self._safe_short(row_id, 50)] = detail

        def add():
            self._table_model.addRow(row)
            last_row = self._table_model.getRowCount() - 1
            self._results_table.scrollRectToVisible(
                self._results_table.getCellRect(last_row, 0, True)
            )

        SwingUtilities.invokeLater(add)

        return self._safe_short(row_id, 50)

    def update_row(self, row_id, status_code, resp_len, result, evidence, detail):
        row_id = self._safe_short(row_id, 50)
        self._details[row_id] = detail

        def update():
            rows = self._table_model.getRowCount()

            for i in range(rows):
                current_id = self._table_model.getValueAt(i, 0)

                if self._safe_short(current_id, 50) == row_id:
                    self._table_model.setValueAt(self._safe_short(status_code, 50), i, 7)
                    self._table_model.setValueAt(self._safe_short(resp_len, 50), i, 8)
                    self._table_model.setValueAt(self._safe_short(result, 50), i, 9)
                    self._table_model.setValueAt(self._safe_short(evidence, 350), i, 10)
                    break

        SwingUtilities.invokeLater(update)

    def _show_selected_detail(self):
        try:
            row = self._results_table.getSelectedRow()
            if row < 0:
                return

            model_row = self._results_table.convertRowIndexToModel(row)
            row_id = self._safe_short(self._table_model.getValueAt(model_row, 0), 50)
            detail = self._details.get(row_id, "")

            self._detail_area.setText(detail)
            self._detail_area.setCaretPosition(0)

        except Exception as e:
            self._log("[!] Could not show detail: %s" % self._safe_short(e, 1000))

    # =========================
    # Mutation: replace ALL body params
    # =========================

    def mutate_all_params_request(self, base_request, param_snapshots, payload=None):
        if payload is None:
            payload = self._payload
        request_info = self._helpers.analyzeRequest(base_request)
        headers = list(request_info.getHeaders())
        body_offset = request_info.getBodyOffset()

        body_bytes = base_request[body_offset:]
        body_text = self._helpers.bytesToString(body_bytes)

        # If all body params are JSON, mutate JSON body directly.
        all_json = True
        for p in param_snapshots:
            if p["type"] != 6:
                all_json = False
                break

        if all_json:
            return self._mutate_all_json_body(headers, body_text, payload)

        # Fallback for x-www-form-urlencoded / XML / multipart:
        # apply Burp updateParameter repeatedly on the same request.
        mutated = base_request[:]

        for p in param_snapshots:
            new_param = self._helpers.buildParameter(
                p["name"],
                payload,
                p["type"]
            )
            mutated = self._helpers.updateParameter(mutated, new_param)

        mutated = self._add_header(mutated, self._marker_header)
        return mutated

    def _mutate_all_json_body(self, headers, body_text, payload):
        try:
            body_unicode = self._to_unicode(body_text)
            data = json.loads(body_unicode)

            count = self._replace_all_json_values(data, payload)

            if count == 0:
                raise Exception("No JSON value was replaced")

            new_body = json.dumps(data, ensure_ascii=False)

            clean_headers = []
            for h in headers:
                h_unicode = self._to_unicode(h)

                if h_unicode.lower().startswith(u"x-auto-sqli-check:"):
                    continue

                # buildHttpMessage recalculates Content-Length.
                if h_unicode.lower().startswith(u"content-length:"):
                    continue

                clean_headers.append(h)

            clean_headers.append(self._marker_header)

            return self._helpers.buildHttpMessage(
                clean_headers,
                new_body.encode("utf-8")
            )

        except Exception as e:
            raise Exception("JSON mutate-all failed: %s" % self._safe_short(e, 1000))

    def _replace_all_json_values(self, obj, payload):
        count = 0

        if isinstance(obj, dict):
            for k in obj.keys():
                v = obj[k]

                if isinstance(v, dict) or isinstance(v, list):
                    count += self._replace_all_json_values(v, payload)
                else:
                    obj[k] = payload
                    count += 1

        elif isinstance(obj, list):
            for i in range(len(obj)):
                v = obj[i]

                if isinstance(v, dict) or isinstance(v, list):
                    count += self._replace_all_json_values(v, payload)
                else:
                    obj[i] = payload
                    count += 1

        return count

    # =========================
    # Send / update
    # =========================

    def _send_request_wait(self, req_id, service, request_bytes, label):
        try:
            self._log("[REQ-%s] [SEND_%s] Sending request" % (
                self._safe_short(req_id, 50),
                self._safe_short(label, 50)
            ))

            network_worker = NetworkRequestWorker(self, service, request_bytes)
            network_thread = Thread(network_worker)
            network_thread.start()

            timeout_ms = self._get_timeout_ms()
            network_thread.join(timeout_ms)

            if network_thread.isAlive():
                return {
                    "ok": False,
                    "result": "TIMEOUT",
                    "evidence": "Timeout after %s ms. Check upstream proxy or server route." % self._safe_short(timeout_ms, 50),
                    "rr": None,
                    "response": None,
                    "status_code": "",
                    "resp_len": "",
                    "response_text": "",
                    "response_preview": ""
                }

            if network_worker.error_text is not None:
                return {
                    "ok": False,
                    "result": "SEND_ERROR",
                    "evidence": "Send failed: %s" % self._safe_short(network_worker.error_text, 1000),
                    "rr": None,
                    "response": None,
                    "status_code": "",
                    "resp_len": "",
                    "response_text": "",
                    "response_preview": ""
                }

            rr = network_worker.rr
            if rr is None:
                return {
                    "ok": False,
                    "result": "SEND_ERROR",
                    "evidence": "makeHttpRequest() returned None",
                    "rr": None,
                    "response": None,
                    "status_code": "",
                    "resp_len": "",
                    "response_text": "",
                    "response_preview": ""
                }

            response = rr.getResponse()
            if response is None:
                return {
                    "ok": False,
                    "result": "NO_RESPONSE",
                    "evidence": "No HTTP response received",
                    "rr": rr,
                    "response": None,
                    "status_code": "",
                    "resp_len": "",
                    "response_text": "",
                    "response_preview": ""
                }

            response_info = self._helpers.analyzeResponse(response)
            status_code = response_info.getStatusCode()
            resp_len = len(response)
            response_text = self._helpers.bytesToString(response)
            response_preview = self._safe_short(response_text, 12000)

            return {
                "ok": True,
                "result": "OK",
                "evidence": "HTTP response received",
                "rr": rr,
                "response": response,
                "status_code": status_code,
                "resp_len": resp_len,
                "response_text": response_text,
                "response_preview": response_preview
            }

        except Exception as e:
            return {
                "ok": False,
                "result": "ERROR",
                "evidence": "Unexpected send error: %s" % self._safe_short(e, 1000),
                "rr": None,
                "response": None,
                "status_code": "",
                "resp_len": "",
                "response_text": "",
                "response_preview": ""
            }

    def _response_body_text(self, response_bytes):
        if response_bytes is None:
            return u""

        try:
            response_info = self._helpers.analyzeResponse(response_bytes)
            body_offset = response_info.getBodyOffset()
            body_bytes = response_bytes[body_offset:]
            return self._helpers.bytesToString(body_bytes)
        except:
            return u""

    def _is_exact_unexpected_error_response(self, response_bytes):
        body_text = self._response_body_text(response_bytes)
        if body_text is None:
            return False

        body_text = self._to_unicode(body_text).strip()

        # Exact JSON structure requested by user:
        # {"Code":1000,"Data":{"TypeName":"System.Exception","Message":"An unexpected error occurred."}}
        try:
            data = json.loads(body_text)
            if not isinstance(data, dict):
                return False

            if data.get("Code") != 1000:
                return False

            d = data.get("Data")
            if not isinstance(d, dict):
                return False

            return (
                d.get("TypeName") == "System.Exception" and
                d.get("Message") == "An unexpected error occurred."
            )
        except:
            compact = re.sub(r"\s+", "", body_text)
            return compact == u'{"Code":1000,"Data":{"TypeName":"System.Exception","Message":"Anunexpectederroroccurred."}}'

    def _combined_preview(self, first_label, first_response_preview, confirm_label, confirm_response_preview):
        return (
            u"==================== RESPONSE FOR %s ====================\n%s\n\n"
            u"==================== RESPONSE FOR %s ====================\n%s"
        ) % (
            self._safe_short(first_label, 100),
            self._safe_short(first_response_preview, 12000),
            self._safe_short(confirm_label, 100),
            self._safe_short(confirm_response_preview, 12000)
        )

    def run_all_params_test(self, req_id, service, base_request, original_request_text,
                            method, url, row_id, param_snapshots, fields_summary):
        fields_count = len(param_snapshots)
        mutated_request = None
        confirm_request = None
        mutated_request_text = ""
        confirm_request_text = ""

        try:
            self._log("[REQ-%s] [MUTATE_1] Replacing %s fields with payload '" % (
                self._safe_short(req_id, 50),
                self._safe_short(fields_count, 50)
            ))

            mutated_request = self.mutate_all_params_request(base_request, param_snapshots, self._payload)
            mutated_request_text = self._helpers.bytesToString(mutated_request)

            detail = self._build_detail(
                result="SENDING_'",
                evidence="All parsed body fields were replaced with payload '. Sending first test.",
                req_id=req_id,
                method=method,
                url=url,
                fields_count=fields_count,
                fields_summary=fields_summary,
                original_request_text=original_request_text,
                mutated_request_text=mutated_request_text,
                status_code="",
                resp_len="",
                response_preview=""
            )
            self.update_row(row_id, "", "", "SENDING_'", "Sending payload ' ...", detail)

        except Exception as e:
            evidence = "Mutation failed for payload ': %s" % self._safe_short(e, 1000)
            detail = self._build_detail(
                result="MUTATE_ERROR",
                evidence=evidence,
                req_id=req_id,
                method=method,
                url=url,
                fields_count=fields_count,
                fields_summary=fields_summary,
                original_request_text=original_request_text,
                mutated_request_text=mutated_request_text,
                status_code="",
                resp_len="",
                response_preview=""
            )
            self.update_row(row_id, "", "", "MUTATE_ERROR", evidence, detail)
            self._log("[REQ-%s] [MUTATE_ERROR] %s" % (
                self._safe_short(req_id, 50),
                self._safe_short(evidence, 1500)
            ))
            return

        first = self._send_request_wait(req_id, service, mutated_request, "SINGLE_QUOTE")

        if not first["ok"]:
            detail = self._build_detail(
                result=first["result"],
                evidence=first["evidence"],
                req_id=req_id,
                method=method,
                url=url,
                fields_count=fields_count,
                fields_summary=fields_summary,
                original_request_text=original_request_text,
                mutated_request_text=mutated_request_text,
                status_code=first["status_code"],
                resp_len=first["resp_len"],
                response_preview=first["response_preview"]
            )
            self.update_row(row_id, first["status_code"], first["resp_len"], first["result"], first["evidence"], detail)
            self._log("[REQ-%s] [%s] %s" % (
                self._safe_short(req_id, 50),
                self._safe_short(first["result"], 50),
                self._safe_short(first["evidence"], 1500)
            ))
            return

        first_exact_generic = self._is_exact_unexpected_error_response(first["response"])
        first_sql_error = self._looks_like_sql_error(first["response_text"])

        if first_exact_generic:
            first_evidence = "Exact generic exception JSON appeared with payload ': " + self._extract_evidence(first["response_text"])
        elif first_sql_error:
            first_evidence = self._extract_evidence(first["response_text"])
        else:
            result = "OK"
            evidence = "No suspicious error pattern detected for payload '"
            detail = self._build_detail(
                result=result,
                evidence=evidence,
                req_id=req_id,
                method=method,
                url=url,
                fields_count=fields_count,
                fields_summary=fields_summary,
                original_request_text=original_request_text,
                mutated_request_text=mutated_request_text,
                status_code=first["status_code"],
                resp_len=first["resp_len"],
                response_preview=first["response_preview"]
            )
            self.update_row(row_id, first["status_code"], first["resp_len"], result, evidence, detail)
            self._log("[REQ-%s] [OK] status=%s | len=%s" % (
                self._safe_short(req_id, 50),
                self._safe_short(first["status_code"], 50),
                self._safe_short(first["resp_len"], 50)
            ))
            return

        # First request is suspicious. Retest the ORIGINAL request with doubled quote ''.
        try:
            self._log("[REQ-%s] [SUSPECT] payload ' caused suspicious error. Retesting with payload ''" % self._safe_short(req_id, 50))
            confirm_request = self.mutate_all_params_request(base_request, param_snapshots, self._payload_confirm)
            confirm_request_text = self._helpers.bytesToString(confirm_request)

            combined_mutated_requests = (
                u"==================== REQUEST WITH PAYLOAD ' ====================\n%s\n\n"
                u"==================== REQUEST WITH PAYLOAD '' ====================\n%s"
            ) % (
                self._safe_short(mutated_request_text, 12000),
                self._safe_short(confirm_request_text, 12000)
            )

            detail = self._build_detail(
                result="SUSPECT_RETESTING",
                evidence="Payload ' triggered suspicious error. Retesting same original request with payload ''.",
                req_id=req_id,
                method=method,
                url=url,
                fields_count=fields_count,
                fields_summary=fields_summary,
                original_request_text=original_request_text,
                mutated_request_text=combined_mutated_requests,
                status_code=first["status_code"],
                resp_len=first["resp_len"],
                response_preview=first["response_preview"]
            )
            self.update_row(row_id, first["status_code"], first["resp_len"], "SUSPECT_RETESTING", first_evidence, detail)

        except Exception as e:
            evidence = "Suspicious with payload ', but confirm mutation with '' failed: %s" % self._safe_short(e, 1000)
            detail = self._build_detail(
                result="SUSPECT_CONFIRM_MUTATE_ERROR",
                evidence=evidence,
                req_id=req_id,
                method=method,
                url=url,
                fields_count=fields_count,
                fields_summary=fields_summary,
                original_request_text=original_request_text,
                mutated_request_text=mutated_request_text,
                status_code=first["status_code"],
                resp_len=first["resp_len"],
                response_preview=first["response_preview"]
            )
            self.update_row(row_id, first["status_code"], first["resp_len"], "SUSPECT", evidence, detail)
            return

        second = self._send_request_wait(req_id, service, confirm_request, "DOUBLE_QUOTE")

        if not second["ok"]:
            result = "SUSPECT_CONFIRM_ERROR"
            evidence = "Payload ' was suspicious, but confirm request failed: %s" % second["evidence"]
            combined_preview = self._combined_preview("PAYLOAD '", first["response_preview"], "PAYLOAD ''", second["response_preview"])
            detail = self._build_detail(
                result=result,
                evidence=evidence,
                req_id=req_id,
                method=method,
                url=url,
                fields_count=fields_count,
                fields_summary=fields_summary,
                original_request_text=original_request_text,
                mutated_request_text=combined_mutated_requests,
                status_code=first["status_code"],
                resp_len=first["resp_len"],
                response_preview=combined_preview
            )
            self.update_row(row_id, first["status_code"], first["resp_len"], result, evidence, detail)
            return

        second_exact_generic = self._is_exact_unexpected_error_response(second["response"])
        second_sql_error = self._looks_like_sql_error(second["response_text"])
        combined_preview = self._combined_preview("PAYLOAD '", first["response_preview"], "PAYLOAD ''", second["response_preview"])

        if first_exact_generic and not second_exact_generic and not second_sql_error:
            result = "SUSPECT_CONFIRMED"
            evidence = "Payload ' returned exact generic exception JSON; payload '' no longer returned that error. Possible quote-breaking SQLi."
        elif first_exact_generic and second_exact_generic:
            result = "SUSPECT_STILL_GENERIC"
            evidence = "Payload ' returned exact generic exception JSON, but payload '' still returned the same generic error. Needs manual verification."
        elif first_sql_error and not second_sql_error and not second_exact_generic:
            result = "FOUND_CONFIRMED"
            evidence = "Payload ' returned SQL/generic error; payload '' no longer returned error. " + self._safe_short(first_evidence, 800)
        else:
            result = "SUSPECT_UNCONFIRMED"
            evidence = "Payload ' was suspicious, but payload '' did not clearly remove the error. Manual verification needed. First evidence: " + self._safe_short(first_evidence, 700)

        issue_messages = [first["rr"]]
        if second["rr"] is not None:
            issue_messages.append(second["rr"])

        if result in ["SUSPECT_CONFIRMED", "FOUND_CONFIRMED", "SUSPECT_STILL_GENERIC", "SUSPECT_UNCONFIRMED"]:
            issue = CustomScanIssue(
                http_service=service,
                url=url,
                http_messages=issue_messages,
                name="Possible SQL Injection - Quote Error Differential",
                detail=(
                    "The extension replaced all parsed body parameters with a single quote payload "
                    "<code>'</code>. The first response was suspicious. It then retested the "
                    "same original request with doubled quote payload <code>''</code>."
                    "<br><br>"
                    "<b>Request ID:</b> %s<br>"
                    "<b>Fields replaced:</b> %s<br>"
                    "<b>First payload:</b> <code>'</code><br>"
                    "<b>Confirm payload:</b> <code>''</code><br>"
                    "<b>Result:</b> %s<br>"
                    "<b>First HTTP status/length:</b> %s / %s<br>"
                    "<b>Confirm HTTP status/length:</b> %s / %s<br>"
                    "<b>Evidence:</b> <code>%s</code><br><br>"
                    "Manual field-by-field verification is required to identify the exact vulnerable parameter."
                ) % (
                    self._html_escape(req_id),
                    self._html_escape(fields_count),
                    self._html_escape(result),
                    self._html_escape(first["status_code"]),
                    self._html_escape(first["resp_len"]),
                    self._html_escape(second["status_code"]),
                    self._html_escape(second["resp_len"]),
                    self._html_escape(evidence)
                ),
                severity="Medium",
                confidence="Tentative"
            )
            self._callbacks.addScanIssue(issue)

        detail = self._build_detail(
            result=result,
            evidence=evidence,
            req_id=req_id,
            method=method,
            url=url,
            fields_count=fields_count,
            fields_summary=fields_summary,
            original_request_text=original_request_text,
            mutated_request_text=combined_mutated_requests,
            status_code=("%s / %s" % (self._safe_short(first["status_code"], 50), self._safe_short(second["status_code"], 50))),
            resp_len=("%s / %s" % (self._safe_short(first["resp_len"], 50), self._safe_short(second["resp_len"], 50))),
            response_preview=combined_preview
        )

        self.update_row(
            row_id,
            "%s/%s" % (self._safe_short(first["status_code"], 50), self._safe_short(second["status_code"], 50)),
            "%s/%s" % (self._safe_short(first["resp_len"], 50), self._safe_short(second["resp_len"], 50)),
            result,
            evidence,
            detail
        )

        self._log("[REQ-%s] [%s] first=%s len=%s | confirm=%s len=%s | %s" % (
            self._safe_short(req_id, 50),
            self._safe_short(result, 50),
            self._safe_short(first["status_code"], 50),
            self._safe_short(first["resp_len"], 50),
            self._safe_short(second["status_code"], 50),
            self._safe_short(second["resp_len"], 50),
            self._safe_short(evidence, 700)
        ))

    # =========================
    # Detail
    # =========================

    def _build_detail(self, result, evidence, req_id, method, url,
                      fields_count, fields_summary, original_request_text,
                      mutated_request_text, status_code, resp_len,
                      response_preview):
        try:
            return (
                u"RESULT: %s\n"
                u"EVIDENCE: %s\n\n"
                u"REQUEST ID: %s\n"
                u"ENDPOINT: %s %s\n"
                u"FIELDS REPLACED: %s\n"
                u"PAYLOAD: %s\n"
                u"HTTP STATUS: %s\n"
                u"RESPONSE LENGTH: %s\n\n"
                u"==================== ALL PARSED BODY FIELDS IN THIS REQUEST ====================\n"
                u"%s\n\n"
                u"==================== ORIGINAL REQUEST ====================\n"
                u"%s\n\n"
                u"==================== MUTATED REQUEST SENT BY EXTENSION ====================\n"
                u"%s\n\n"
                u"==================== RESPONSE PREVIEW ====================\n"
                u"%s\n"
            ) % (
                self._safe_short(result, 500),
                self._safe_short(evidence, 1500),
                self._safe_short(req_id, 100),
                self._safe_short(method, 50),
                self._safe_short(url, 1000),
                self._safe_short(fields_count, 100),
                self._safe_short(self._payload, 100),
                self._safe_short(status_code, 100),
                self._safe_short(resp_len, 100),
                self._safe_short(fields_summary, 12000),
                self._safe_short(original_request_text, 12000),
                self._safe_short(mutated_request_text, 12000),
                self._safe_short(response_preview, 12000)
            )
        except Exception as e:
            return u"BUILD DETAIL ERROR: %s" % self._safe_short(e, 1000)

    # =========================
    # SQL error detection
    # =========================

    def _looks_like_sql_error(self, response_text):
        if response_text is None:
            return False

        text = self._to_unicode(response_text)
        text = text.replace(u"\\r", u" ") \
                   .replace(u"\\n", u" ") \
                   .replace(u"\r", u" ") \
                   .replace(u"\n", u" ")

        if self._sql_error_regex.search(text):
            return True

        lower = text.lower()

        has_exception_type = (
            u"sqlexception" in lower or
            u"system.data.sqlclient" in lower or
            u"microsoft.data.sqlclient" in lower
        )

        has_sql_message = (
            u"incorrect syntax near" in lower or
            u"unclosed quotation mark" in lower or
            u"conversion failed" in lower or
            u"error converting data type" in lower or
            u"invalid column name" in lower or
            u"invalid object name" in lower or
            u"must declare the scalar variable" in lower
        )

        if has_exception_type and has_sql_message:
            return True

        strong_mssql_messages = [
            u"incorrect syntax near",
            u"unclosed quotation mark after the character string",
            u"unclosed quotation mark",
            u"conversion failed when converting",
            u"error converting data type"
        ]

        for indicator in strong_mssql_messages:
            if indicator in lower:
                return True

        return False

    def _extract_evidence(self, response_text):
        if response_text is None:
            return u""

        text = self._to_unicode(response_text)
        text = text.replace(u"\\r", u" ") \
                   .replace(u"\\n", u" ") \
                   .replace(u"\r", u" ") \
                   .replace(u"\n", u" ")

        indicators = [
            u"System.Data.SqlClient.SqlException",
            u"Microsoft.Data.SqlClient.SqlException",
            u"SqlException",
            u"Incorrect syntax near",
            u"Unclosed quotation mark",
            u"Conversion failed when converting",
            u"Error converting data type",
            u"Invalid column name",
            u"Invalid object name",
            u"Must declare the scalar variable",
            u"SQL syntax",
            u"syntax error",
            u"ORA-",
            u"PostgreSQL",
            u"MySQL server version",
            u"SQLiteException",
            u"An unexpected error occurred.",
            u"System.Exception"
        ]

        lower = text.lower()

        for indicator in indicators:
            pos = lower.find(indicator.lower())

            if pos >= 0:
                start = max(0, pos - 150)
                end = min(len(text), pos + 500)
                return text[start:end]

        return text[:500]

    # =========================
    # Request helpers
    # =========================

    def _add_header(self, request_bytes, header_line):
        request_info = self._helpers.analyzeRequest(request_bytes)
        headers = list(request_info.getHeaders())

        clean_headers = []

        for h in headers:
            h_unicode = self._to_unicode(h)

            if h_unicode.lower().startswith(u"x-auto-sqli-check:"):
                continue

            clean_headers.append(h)

        clean_headers.append(header_line)

        body_offset = request_info.getBodyOffset()
        body = request_bytes[body_offset:]

        return self._helpers.buildHttpMessage(clean_headers, body)

    # =========================
    # String helpers
    # =========================

    def _to_unicode(self, s):
        if s is None:
            return u""

        try:
            return unicode(s)
        except:
            try:
                return unicode(str(s), "utf-8", "ignore")
            except:
                return u"<unicode-convert-error>"

    def _safe_short(self, s, max_len):
        if s is None:
            return u""

        try:
            s = self._to_unicode(s)
            s = s.replace(u"\r", u" ").replace(u"\n", u" ")
            s = s.replace(u"\\r", u" ").replace(u"\\n", u" ")

            if len(s) > max_len:
                return s[:max_len] + u"..."

            return s
        except:
            return u"<safe-short-error>"

    def _html_escape(self, s):
        if s is None:
            return u""

        s = self._to_unicode(s)

        return s.replace(u"&", u"&amp;") \
                .replace(u"<", u"&lt;") \
                .replace(u">", u"&gt;") \
                .replace(u'"', u"&quot;") \
                .replace(u"'", u"&#x27;")


class AllParamsTestWorker(Runnable):

    def __init__(self, ext, req_id, service, base_request, original_request_text,
                 method, url, row_id, param_snapshots, fields_summary):
        self.ext = ext
        self.req_id = req_id
        self.service = service
        self.base_request = base_request
        self.original_request_text = original_request_text
        self.method = method
        self.url = url
        self.row_id = row_id
        self.param_snapshots = param_snapshots
        self.fields_summary = fields_summary

    def run(self):
        self.ext.run_all_params_test(
            self.req_id,
            self.service,
            self.base_request,
            self.original_request_text,
            self.method,
            self.url,
            self.row_id,
            self.param_snapshots,
            self.fields_summary
        )


class NetworkRequestWorker(Runnable):

    def __init__(self, ext, service, mutated_request):
        self.ext = ext
        self.service = service
        self.mutated_request = mutated_request
        self.rr = None
        self.error_text = None

    def run(self):
        try:
            self.rr = self.ext._callbacks.makeHttpRequest(
                self.service,
                self.mutated_request
            )
        except Exception as e:
            self.error_text = self.ext._safe_short(e, 1000)


class RowSelectionListener(ListSelectionListener):

    def __init__(self, ext):
        self.ext = ext

    def valueChanged(self, event):
        if event.getValueIsAdjusting():
            return

        self.ext._show_selected_detail()


class CustomScanIssue(IScanIssue):

    def __init__(self, http_service, url, http_messages, name, detail, severity, confidence):
        self._http_service = http_service
        self._url = url
        self._http_messages = http_messages
        self._name = name
        self._detail = detail
        self._severity = severity
        self._confidence = confidence

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return self._confidence

    def getIssueBackground(self):
        return (
            "SQL Injection may occur when user-controlled input is concatenated "
            "into SQL queries without proper parameterization. Error-based SQL "
            "Injection is often indicated by database-specific error messages "
            "being returned to the client."
        )

    def getRemediationBackground(self):
        return (
            "Use parameterized queries or prepared statements. Avoid building SQL "
            "queries through string concatenation. Implement centralized exception "
            "handling and avoid returning raw database errors to users."
        )

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return (
            "Manually verify which specific parameter reaches a SQL query. "
            "If confirmed, replace dynamic SQL string concatenation with safe query "
            "APIs such as parameterized queries, prepared statements, or ORM-safe "
            "binding. Return generic error messages to clients and log detailed "
            "database errors server-side only."
        )

    def getHttpMessages(self):
        return self._http_messages

    def getHttpService(self):
        return self._http_service