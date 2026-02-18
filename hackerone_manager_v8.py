import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import json
import requests
from requests.auth import HTTPBasicAuth
import threading
import time
import os
import csv
from datetime import datetime
import traceback

# --- CONFIGURATION ---
CONFIG_FILE = "team_config_v8.json"

DEFAULT_MSG = "Thank you for bringing this to our attention. We have received your report and are now validating the issue internally. We will get back to you soon."

DEFAULT_DATA = {
    "api_id": "",          
    "api_token": "",       
    "program_handle": "",
    "lark_webhook": "", 
    "use_hai": False,
    "ai_threshold": 80,
    "comment_template": DEFAULT_MSG,
    "members": [], 
    "history": []
}

class H1ManagerApp(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("HackerOne Automation")
        self.geometry("1400x900")
        
        # --- STYLE ---
        style = ttk.Style()
        style.theme_use('clam') 
        self.configure(bg="#ecf0f1")
        
        self.data = self.load_data()
        self.is_scanning = False
        self.sort_col = None
        self.sort_reverse = False
        self.current_filter = "All"
        
        # --- LAYOUT SETUP ---
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)
        
        container = ttk.Frame(self, padding=10)
        container.grid(row=0, column=0, sticky="nsew")
        container.columnconfigure(0, weight=1)
        container.rowconfigure(0, weight=1)

        self.notebook = ttk.Notebook(container)
        self.notebook.grid(row=0, column=0, sticky="nsew")

        # --- INITIALIZE TABS ---
        # 1. Dashboard
        self.tab_dashboard = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(self.tab_dashboard, text="  🤖 Operations Center  ")
        self.setup_dashboard()

        # 2. Team Database
        self.tab_teams = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(self.tab_teams, text="  👥 Team Database  ")
        self.setup_team_management()

        # 3. Settings
        self.tab_settings = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(self.tab_settings, text="  ⚙️ Configuration  ")
        self.setup_settings()
        
        # Status Bar
        self.status_var = tk.StringVar(value="Ready")
        self.status_bar = ttk.Label(self, textvariable=self.status_var, relief=tk.SUNKEN, anchor="e")
        self.status_bar.grid(row=1, column=0, sticky="ew", padx=10, pady=5)

    # --- DATA HANDLING ---
    def load_data(self):
        if not os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'w') as f:
                json.dump(DEFAULT_DATA, f, indent=4)
            return DEFAULT_DATA
        else:
            try:
                with open(CONFIG_FILE, 'r') as f:
                    d = json.load(f)
                    # Ensure all keys exist to prevent crashes on old config files
                    if "members" not in d: d["members"] = []
                    if "ai_threshold" not in d: d["ai_threshold"] = 80
                    if "comment_template" not in d: d["comment_template"] = DEFAULT_MSG
                    if "lark_webhook" not in d: d["lark_webhook"] = ""
                    return d
            except:
                return DEFAULT_DATA

    def save_data(self):
        with open(CONFIG_FILE, 'w') as f:
            json.dump(self.data, f, indent=4)

    # ==========================================
    # TAB 1: DASHBOARD
    # ==========================================
    def setup_dashboard(self):
        self.tab_dashboard.columnconfigure(0, weight=1)
        self.tab_dashboard.rowconfigure(1, weight=1)

        # Controls
        control_frame = ttk.LabelFrame(self.tab_dashboard, text="Automation Controls", padding=15)
        control_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        
        self.btn_scan = ttk.Button(control_frame, text="⚡ Scan New Reports", command=self.run_scan_thread)
        self.btn_scan.pack(side=tk.LEFT, padx=5)

        self.var_auto = tk.BooleanVar(value=False)
        self.chk_auto = ttk.Checkbutton(control_frame, text="Auto-Loop (60s)", variable=self.var_auto, command=self.toggle_auto)
        self.chk_auto.pack(side=tk.LEFT, padx=20)
        
        self.var_hai = tk.BooleanVar(value=self.data.get('use_hai', False))
        self.chk_hai = ttk.Checkbutton(control_frame, text="Enable Hai (AI Triage)", variable=self.var_hai, command=self.save_ai_toggle)
        self.chk_hai.pack(side=tk.LEFT, padx=20)

        # Threshold Slider
        ttk.Label(control_frame, text="Min Confidence:").pack(side=tk.LEFT, padx=(15, 5))
        self.lbl_thresh = ttk.Label(control_frame, text=f"{self.data.get('ai_threshold', 80)}%")
        self.lbl_thresh.pack(side=tk.LEFT, padx=2)
        
        self.scale_thresh = ttk.Scale(control_frame, from_=50, to=100, orient=tk.HORIZONTAL, command=self.update_thresh_label)
        self.scale_thresh.set(self.data.get('ai_threshold', 80))
        self.scale_thresh.pack(side=tk.LEFT, padx=5)

        ttk.Button(control_frame, text="📜 View History", command=self.show_history_window).pack(side=tk.RIGHT, padx=5)

        # Logs
        log_frame = ttk.LabelFrame(self.tab_dashboard, text="Live Activity Log", padding=10)
        log_frame.grid(row=1, column=0, sticky="nsew")
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)

        self.log_box = scrolledtext.ScrolledText(log_frame, state='disabled', bg="#1e1e1e", fg="#ecf0f1", font=("Consolas", 10), insertbackground="white")
        self.log_box.grid(row=0, column=0, sticky="nsew")
        
        self.log_box.tag_config("INFO", foreground="#ecf0f1")
        self.log_box.tag_config("SUCCESS", foreground="#2ecc71") 
        self.log_box.tag_config("ERROR", foreground="#e74c3c")   
        self.log_box.tag_config("WARN", foreground="#f1c40f")    
        self.log_box.tag_config("AI", foreground="#3498db")      
        self.log_box.tag_config("SUMMARY", foreground="#9b59b6")

        # Manual Override
        override_frame = ttk.LabelFrame(self.tab_dashboard, text="Manual Assignment Override", padding=15)
        override_frame.grid(row=2, column=0, sticky="ew", pady=(10, 0))

        ttk.Label(override_frame, text="Report ID:").pack(side=tk.LEFT, padx=5)
        self.ent_debug_rid = ttk.Entry(override_frame, width=15)
        self.ent_debug_rid.pack(side=tk.LEFT, padx=5)

        ttk.Label(override_frame, text="User ID (Numeric):").pack(side=tk.LEFT, padx=5)
        self.ent_debug_uid = ttk.Entry(override_frame, width=15)
        self.ent_debug_uid.pack(side=tk.LEFT, padx=5)

        ttk.Button(override_frame, text="🚀 Force Assign", command=self.force_assign_debug).pack(side=tk.LEFT, padx=20)

    def update_thresh_label(self, val):
        v = int(float(val))
        self.lbl_thresh.config(text=f"{v}%")
        self.data['ai_threshold'] = v

    def log(self, message, level="INFO"):
        self.log_box.config(state='normal')
        ts = datetime.now().strftime("[%H:%M:%S] ")
        self.log_box.insert(tk.END, ts, "INFO")
        self.log_box.insert(tk.END, f"{message}\n", level)
        self.log_box.see(tk.END)
        self.log_box.config(state='disabled')
        self.status_var.set(f"Last Action: {message[:60]}...")

    def save_ai_toggle(self):
        self.data['use_hai'] = self.var_hai.get()
        self.save_data()

    def force_assign_debug(self):
        rid = self.ent_debug_rid.get().strip()
        user_input = self.ent_debug_uid.get().strip()
        if not rid or not user_input:
            messagebox.showerror("Error", "Enter both IDs")
            return
        self.log(f"Manual Override: Report #{rid} -> User '{user_input}'", "WARN")
        
        # 1. Assign
        if self.assign_api_call(rid, user_input):
            # 2. Comment
            self.post_public_comment(rid)
            
            # 3. Notify
            name = "Unknown"
            for m in self.data['members']:
                if str(m['id']) == user_input:
                    m['count'] += 1
                    name = m['name']
            
            self.send_lark_card(rid, "Manual Override Report", name, "MANUAL", "Manual Force Assignment")
            self.save_data()
            self.refresh_table()

    # ==========================================
    # TAB 2: USER MANAGEMENT
    # ==========================================
    def setup_team_management(self):
        self.tab_teams.columnconfigure(0, weight=1)
        self.tab_teams.rowconfigure(1, weight=1)

        # Toolbar
        toolbar = ttk.Frame(self.tab_teams)
        toolbar.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        
        ttk.Button(toolbar, text="🔄 Sync Users from H1", command=self.sync_h1_users_thread).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="📂 Import CSV", command=self.import_internal_csv).pack(side=tk.LEFT, padx=2)
        
        ttk.Separator(toolbar, orient=tk.VERTICAL).pack(side=tk.LEFT, padx=10, fill=tk.Y)
        
        ttk.Label(toolbar, text="Filter:").pack(side=tk.LEFT)
        self.combo_filter = ttk.Combobox(toolbar, values=["All Users", "Web Team", "Mobile Team", "IoT Team", "N/A"], state="readonly", width=15)
        self.combo_filter.current(0)
        self.combo_filter.pack(side=tk.LEFT, padx=5)
        self.combo_filter.bind("<<ComboboxSelected>>", self.apply_filter)

        ttk.Button(toolbar, text="🗑️ Delete", command=self.mass_delete).pack(side=tk.RIGHT)
        ttk.Button(toolbar, text="+ Add User", command=self.add_new_member).pack(side=tk.RIGHT, padx=5)

        # Treeview
        columns = ("active", "h1_name", "email", "team", "role", "load", "h1_id")
        self.tree = ttk.Treeview(self.tab_teams, columns=columns, show='headings', selectmode='extended')
        
        headers = {
            "active": "Status", "h1_name": "Username", "email": "Email", 
            "team": "Team", "role": "Role", "load": "Load", "h1_id": "User ID"
        }
        for col, text in headers.items():
            self.tree.heading(col, text=text, command=lambda _c=col: self.sort_tree(_c))
        
        self.tree.column("active", width=60, anchor='center')
        self.tree.column("load", width=60, anchor='center')
        
        scrollbar = ttk.Scrollbar(self.tab_teams, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        
        self.tree.grid(row=1, column=0, sticky="nsew")
        scrollbar.grid(row=1, column=1, sticky="ns")
        self.tree.bind("<Double-1>", self.edit_current_user_popup)

        # --- BATCH ACTIONS ---
        batch_frame = ttk.LabelFrame(self.tab_teams, text="Batch Actions", padding=10)
        batch_frame.grid(row=2, column=0, sticky="ew", pady=(10, 0))
        
        # Select All Helper
        ttk.Button(batch_frame, text="✅ Select All Rows", command=self.select_all_rows).pack(side=tk.LEFT)
        ttk.Separator(batch_frame, orient=tk.VERTICAL).pack(side=tk.LEFT, padx=10, fill=tk.Y)

        ttk.Label(batch_frame, text="Set Status:").pack(side=tk.LEFT, padx=5)
        self.combo_status_edit = ttk.Combobox(batch_frame, values=["- No Change -", "Active", "Inactive"], state="readonly", width=12)
        self.combo_status_edit.current(0)
        self.combo_status_edit.pack(side=tk.LEFT, padx=5)

        ttk.Label(batch_frame, text="Set Team:").pack(side=tk.LEFT, padx=(15, 5))
        self.combo_team_edit = ttk.Combobox(batch_frame, values=["- No Change -", "web", "mobile", "iot", "N/A"], state="readonly", width=12)
        self.combo_team_edit.current(0)
        self.combo_team_edit.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(batch_frame, text="Apply Changes", command=self.save_batch_edit).pack(side=tk.RIGHT, padx=10)
        
        self.refresh_table()

    # ==========================================
    # TAB 3: SETTINGS
    # ==========================================
    def setup_settings(self):
        f = ttk.Frame(self.tab_settings, padding=20)
        f.pack(fill=tk.BOTH, expand=True)
        ttk.Label(f, text="API ID:").pack(anchor=tk.W)
        self.ent_api_id = ttk.Entry(f); self.ent_api_id.insert(0, self.data['api_id']); self.ent_api_id.pack(fill=tk.X, pady=5)
        ttk.Label(f, text="API Token:").pack(anchor=tk.W)
        self.ent_api_token = ttk.Entry(f, show="*"); self.ent_api_token.insert(0, self.data['api_token']); self.ent_api_token.pack(fill=tk.X, pady=5)
        ttk.Label(f, text="Program Handle:").pack(anchor=tk.W)
        self.ent_program = ttk.Entry(f); self.ent_program.insert(0, self.data['program_handle']); self.ent_program.pack(fill=tk.X, pady=5)
        
        ttk.Label(f, text="Feishu/Lark Webhook URL:").pack(anchor=tk.W, pady=(15, 0))
        
        # Horizontal frame for Input + Test Button
        lark_frame = ttk.Frame(f)
        lark_frame.pack(fill=tk.X, pady=5)
        self.ent_lark = ttk.Entry(lark_frame)
        self.ent_lark.insert(0, self.data.get('lark_webhook', ''))
        self.ent_lark.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        ttk.Button(lark_frame, text="🔔 Test Connection", command=self.test_lark_connection).pack(side=tk.LEFT, padx=(5, 0))

        ttk.Label(f, text="Automated Public Reply Message:").pack(anchor=tk.W, pady=(15, 5))
        self.txt_comment = scrolledtext.ScrolledText(f, height=5, font=("Arial", 10))
        self.txt_comment.pack(fill=tk.X)
        self.txt_comment.insert(tk.END, self.data.get('comment_template', DEFAULT_MSG))

        ttk.Button(f, text="Save Settings", command=self.save_settings_ui).pack(pady=20)

    # ==========================================
    # LOGIC CORE
    # ==========================================
    def run_scan_thread(self):
        if not self.is_scanning:
            self.is_scanning = True
            self.btn_scan.config(state='disabled')
            threading.Thread(target=self.perform_scan, daemon=True).start()

    def perform_scan(self):
        self.log("🔍 Scanning...", "INFO")
        if not self.data['api_id']: return

        stats = {
            "found": 0,
            "assigned": 0,
            "retried_ai": 0,
            "skipped_ai": 0,
            "skipped_member": 0
        }

        try:
            resp = requests.get("https://api.hackerone.com/v1/reports", 
                params={"filter[program][]": self.data['program_handle'], "filter[state][]": "new", "page[size]": 100},
                auth=HTTPBasicAuth(self.data['api_id'], self.data['api_token']), headers={"Accept": "application/json"})
            
            if resp.status_code != 200:
                self.log(f"API Error: {resp.status_code}", "ERROR")
            else:
                unassigned = [r for r in resp.json().get('data', []) if r.get('relationships', {}).get('assignee', {}).get('data') is None]
                stats['found'] = len(unassigned)
                
                if unassigned: 
                    self.log(f"🚨 Found {len(unassigned)} unassigned reports.", "WARN")
                    for r in unassigned: 
                        res, retries = self.process_report(r)
                        stats['retried_ai'] += retries
                        if res == "assigned": stats['assigned'] += 1
                        elif res == "skipped_ai": stats['skipped_ai'] += 1
                        elif res == "skipped_member": stats['skipped_member'] += 1
                else: 
                    self.log("No new reports.", "SUCCESS")
        except Exception as e: 
            self.log(f"Scan Exception: {e}", "ERROR")
        
        if stats['found'] > 0:
            self.log("-" * 40, "SUMMARY")
            self.log(f"📊 SCAN SUMMARY", "SUMMARY")
            self.log(f"   Found: {stats['found']} | Assigned: {stats['assigned']}", "SUMMARY")
            self.log(f"   Retried AI: {stats['retried_ai']} times", "SUMMARY")
            self.log(f"   Skipped (AI Low Conf/Err): {stats['skipped_ai']}", "SUMMARY")
            self.log(f"   Skipped (No User): {stats['skipped_member']}", "SUMMARY")
            self.log("-" * 40, "SUMMARY")

        self.is_scanning = False
        self.btn_scan.config(state='normal')

    def process_report(self, report):
        r_id = report['id']
        title = report.get('attributes', {}).get('title', 'No Title')
        
        self.log(f"📄 Processing: #{r_id} - '{title}'", "INFO")

        team_type = None 
        final_reason = "Manual / Regex Match" 
        
        if self.data.get('use_hai', False):
            for attempt in range(1, 4):
                cat, conf, reason = self.ask_hai_category(r_id)
                min_thresh = self.data.get('ai_threshold', 80)
                
                if cat and conf >= min_thresh:
                    team_type = cat.lower()
                    final_reason = reason
                    self.log(f"🧠 AI: {cat} (Confidence: {conf}%)", "AI")
                    break 
                else:
                    if attempt < 3: self.log(f"⚠️ AI Low Conf ({conf}%). Retrying...", "WARN")
                    else: return "skipped_ai", 0

        if not team_type and self.data.get('use_hai', False):
             return "skipped_ai", 0

        if not team_type: team_type = "web" 

        eligible = [m for m in self.data['members'] if m['team'] == team_type and m['active'] and m['id']]
        
        if not eligible:
            self.log(f"❌ No active members found for team: {team_type.upper()}", "ERROR")
            return "skipped_member", 0

        best = sorted(eligible, key=lambda x: x['count'])[0]
        self.log(f"➤ Assigning to: {best['name']} (Load: {best['count']})", "INFO")

        # --- KEY FIX: self.assign_api_call ---
        if self.assign_api_call(r_id, best['id']):
            
            # --- KEY FIX: self.post_public_comment ---
            self.post_public_comment(r_id)
            
            # --- KEY FIX: self.send_lark_card ---
            self.send_lark_card(r_id, title, best['name'], team_type, final_reason)
            
            best['count'] += 1
            self.data['history'].append({"date": datetime.now().strftime("%Y-%m-%d %H:%M"), "report_id": r_id, "assignee": best['name'], "team": team_type})
            self.save_data()
            self.refresh_table()
            self.log("✅ Assignment Complete", "SUCCESS")
            return "assigned", 0
        
        return "error", 0

    # --- LARK INTEGRATION ---
    def send_lark_card(self, report_id, title, assignee, team, reason):
        webhook = self.data.get('lark_webhook', '')
        if not webhook: return

        reason_clean = str(reason).replace("*", "").strip()[:500] 
        
        card_content = {
            "config": {"wide_screen_mode": True},
            "header": {
                "title": {"tag": "plain_text", "content": "🤖 Report Triaged"},
                "template": "blue"
            },
            "elements": [
                {
                    "tag": "div",
                    "fields": [
                        {"is_short": True, "text": {"tag": "lark_md", "content": f"**Report ID:**\n[#{report_id}](https://hackerone.com/reports/{report_id})"}},
                        {"is_short": True, "text": {"tag": "lark_md", "content": f"**Category:**\n{team.upper()}"}}
                    ]
                },
                {
                    "tag": "div",
                    "text": {"tag": "lark_md", "content": f"**Title:**\n{title}"}
                },
                {"tag": "hr"},
                {
                    "tag": "div",
                    "text": {"tag": "lark_md", "content": f"👉 **Assigned To:** {assignee}\nℹ️ **Reason:** {reason_clean}"}
                }
            ]
        }

        payload = {
            "msg_type": "interactive",
            "card": card_content
        }
        
        try:
            r = requests.post(webhook, json=payload, headers={'Content-Type': 'application/json'})
            if r.status_code == 200:
                resp_json = r.json()
                if resp_json.get("code") == 0:
                    self.log("   🔔 Feishu Card Sent Successfully", "SUCCESS")
                else:
                    self.log(f"   ❌ Feishu Rejected: {resp_json}", "ERROR")
            else:
                self.log(f"   ❌ Feishu HTTP Error: {r.status_code}", "ERROR")
        except Exception as e:
            self.log(f"   ❌ Feishu Exception: {e}", "ERROR")

    # --- TEST CONNECTION ---
    def test_lark_connection(self):
        self.data['lark_webhook'] = self.ent_lark.get().strip()
        self.save_data()
        
        if not self.data['lark_webhook']:
            messagebox.showerror("Error", "Please paste a Webhook URL first.")
            return
            
        self.log("🔔 Sending Test Card to Feishu...", "INFO")
        
        self.send_lark_card(
            report_id="12345 (Test)",
            title="This is a test notification to verify the format.",
            assignee="Test Bot",
            team="TEST",
            reason="Verifying connectivity and visual layout."
        )
        
        messagebox.showinfo("Test Sent", "Check your Feishu/Lark group.\n\nIf you see a Blue Card, it works!\nIf not, check the 'Activity Log' here for errors.")

    # --- AI & API ---
    def ask_hai_category(self, r_id):
        try:
            prompt = (
                "Analyze this report for classification into: WEB, MOBILE, or IOT.\n"
                "You MUST reply in this exact format:\n"
                "CATEGORY: [WEB/MOBILE/IOT]\n"
                "CONFIDENCE: [0-100]\n"
                "REASON: [Short explanation]"
            )
            payload = {"data": {"type": "completion-request", "attributes": {"messages": [{"role": "user", "content": prompt}], "report_ids": [int(r_id)]}}}
            r = requests.post("https://api.hackerone.com/v1/hai/chat/completions", json=payload, auth=HTTPBasicAuth(self.data['api_id'], self.data['api_token']))
            if r.status_code not in [200, 201]: return None, 0, "API Error"
            job_id = r.json()['data'][0]['id'] if isinstance(r.json()['data'], list) else r.json()['data']['id']
            for _ in range(8):
                time.sleep(1.5)
                check = requests.get(f"https://api.hackerone.com/v1/hai/chat/completions/{job_id}", auth=HTTPBasicAuth(self.data['api_id'], self.data['api_token']))
                if check.status_code == 200:
                    state = check.json()['data']['attributes']['state']
                    if state == 'completed':
                        raw = check.json()['data']['attributes']['response'].strip()
                        cat, conf, reason = None, 0, "No reason"
                        lines = raw.split('\n')
                        for line in lines:
                            l = line.upper().strip()
                            if l.startswith("CATEGORY:"):
                                val = l.replace("CATEGORY:", "").strip()
                                if "MOBILE" in val: cat = "mobile"
                                elif "IOT" in val: cat = "iot"
                                elif "WEB" in val: cat = "web"
                            elif l.startswith("CONFIDENCE:"):
                                try: conf = int(''.join(filter(str.isdigit, l)))
                                except: conf = 0
                            elif l.startswith("REASON:"):
                                reason = line.replace("REASON:", "").strip()
                        return cat, conf, reason
            return None, 0, "Timeout"
        except: return None, 0, "Exception"

    def assign_api_call(self, report_id, user_id):
        try:
            url = f"https://api.hackerone.com/v1/reports/{report_id}/assignee"
            payload = {"data": {"type": "user", "id": int(user_id)}}
            r = requests.put(url, json=payload, auth=HTTPBasicAuth(self.data['api_id'], self.data['api_token']))
            if r.status_code == 200: return True
            self.log(f"Assignment Failed: {r.status_code}", "ERROR")
            return False
        except Exception as e: return False

    # --- RESTORED FUNCTION ---
    def post_public_comment(self, report_id):
        try:
            message = self.data.get('comment_template', DEFAULT_MSG)
            if not message.strip(): message = DEFAULT_MSG
            url = f"https://api.hackerone.com/v1/reports/{report_id}/activities"
            payload = {"data": {"type": "activity-comment", "attributes": {"message": message, "internal": False}}}
            requests.post(url, json=payload, auth=HTTPBasicAuth(self.data['api_id'], self.data['api_token']))
        except: pass

    # --- UI & SYNC ---
    def sync_h1_users_thread(self): threading.Thread(target=self.sync_h1_users, daemon=True).start()
    def sync_h1_users(self):
        auth = HTTPBasicAuth(self.data['api_id'], self.data['api_token'])
        try:
            r_org = requests.get('https://api.hackerone.com/v1/me/organizations', auth=auth, headers={'Accept': 'application/json'})
            if r_org.status_code != 200: return
            org_id = r_org.json()['data'][0]['id']
            url = f"https://api.hackerone.com/v1/organizations/{org_id}/members"
            while url:
                r = requests.get(url, auth=auth, headers={'Accept': 'application/json'})
                data = r.json()
                for m in data.get('data', []):
                    attrs = m['attributes']
                    uid = str(attrs['user_id'])
                    exists = next((x for x in self.data['members'] if x['id'] == uid), None)
                    if not exists: self.data['members'].append({"name": attrs['username'], "email": attrs.get('email', ''), "id": uid, "team": "N/A", "role": "Member", "active": True, "count": 0})
                    else: exists['email'] = attrs.get('email', '')
                url = data.get('links', {}).get('next')
            self.save_data(); self.after(0, self.refresh_table)
            self.log(f"✅ Sync Complete", "SUCCESS")
        except: pass

    def toggle_auto(self):
        if self.var_auto.get(): 
            self.log("Starting Auto-Scan Loop...", "INFO")
            threading.Thread(target=self.auto_scan_loop, daemon=True).start()
        else: self.log("Stopping Auto-Scan...", "WARN")

    def auto_scan_loop(self):
        while self.var_auto.get():
            self.perform_scan()
            for _ in range(60):
                if not self.var_auto.get(): break
                time.sleep(1)

    def sort_tree(self, col):
        if self.sort_col == col: self.sort_reverse = not self.sort_reverse
        else: self.sort_reverse = False; self.sort_col = col
        self.data['members'].sort(key=lambda x: str(x.get(col, '')).lower(), reverse=self.sort_reverse)
        self.refresh_table()

    def apply_filter(self, event=None):
        self.current_filter = self.combo_filter.get()
        self.refresh_table()

    def refresh_table(self):
        for item in self.tree.get_children(): self.tree.delete(item)
        for m in self.data['members']:
            if self.current_filter == "Web Team" and m['team'] != "web": continue
            if self.current_filter == "Mobile Team" and m['team'] != "mobile": continue
            if self.current_filter == "IoT Team" and m['team'] != "iot": continue
            if self.current_filter == "N/A" and m['team'] != "N/A": continue
            status = "✅" if m['active'] else "❌"
            self.tree.insert("", "end", values=(status, m['name'], m.get('email',''), m['team'].upper(), m.get('role',''), m['count'], m['id']))

    def add_new_member(self):
        self.data['members'].insert(0, {"name": "New", "id": "", "team": "N/A", "active": True, "count": 0})
        self.refresh_table()

    def mass_delete(self):
        selected = self.tree.selection()
        names = [self.tree.item(i)['values'][1] for i in selected]
        self.data['members'] = [m for m in self.data['members'] if m['name'] not in names]
        self.save_data(); self.refresh_table()

    def edit_current_user_popup(self, event=None):
        selected = self.tree.selection()
        if not selected: return
        h1_name = self.tree.item(selected[0])['values'][1]
        member = next((m for m in self.data['members'] if m['name'] == h1_name), None)
        if not member: return
        top = tk.Toplevel(self); top.title(f"Edit: {h1_name}"); top.geometry("400x450")
        f = ttk.Frame(top, padding=20); f.pack(fill=tk.BOTH, expand=True)
        ttk.Label(f, text="Nickname:").pack(anchor=tk.W); e_name = ttk.Entry(f); e_name.insert(0, member['name']); e_name.pack(fill=tk.X, pady=5)
        ttk.Label(f, text="H1 ID:").pack(anchor=tk.W); e_id = ttk.Entry(f); e_id.insert(0, member['id']); e_id.pack(fill=tk.X, pady=5)
        ttk.Label(f, text="Team:").pack(anchor=tk.W); e_team = ttk.Combobox(f, values=["N/A", "web", "mobile", "iot"], state="readonly"); e_team.set(member['team']); e_team.pack(fill=tk.X, pady=5)
        ttk.Label(f, text="Load:").pack(anchor=tk.W); e_load = ttk.Spinbox(f, from_=0, to=999); e_load.set(member['count']); e_load.pack(fill=tk.X, pady=5)
        def save_and_close():
            member['name'] = e_name.get(); member['id'] = e_id.get().strip(); member['team'] = e_team.get(); member['count'] = int(e_load.get())
            self.save_data(); self.refresh_table(); top.destroy()
        ttk.Button(f, text="💾 Save", command=save_and_close).pack(fill=tk.X, pady=20)

    def select_all_rows(self):
        for item in self.tree.get_children(): self.tree.selection_add(item)

    def save_batch_edit(self):
        selected = self.tree.selection()
        status_choice = self.combo_status_edit.get()
        team_choice = self.combo_team_edit.get()
        for item_id in selected:
            h1_name = self.tree.item(item_id)['values'][1]
            for m in self.data['members']:
                if m['name'] == h1_name:
                    if status_choice == "Active": m['active'] = True
                    elif status_choice == "Inactive": m['active'] = False
                    if team_choice != "- No Change -": m['team'] = team_choice
        self.save_data(); self.refresh_table()

    def show_history_window(self):
        top = tk.Toplevel(self); top.title("History"); top.geometry("600x400")
        txt = scrolledtext.ScrolledText(top); txt.pack(fill=tk.BOTH, expand=True)
        for i in reversed(self.data.get('history', [])): txt.insert(tk.END, f"[{i['date']}] Report #{i['report_id']} -> {i['assignee']} ({i['team']})\n")

    def save_settings_ui(self):
        self.data['api_id'] = self.ent_api_id.get()
        self.data['api_token'] = self.ent_api_token.get()
        self.data['program_handle'] = self.ent_program.get()
        self.data['lark_webhook'] = self.ent_lark.get()
        self.data['comment_template'] = self.txt_comment.get("1.0", tk.END).strip()
        self.save_data()
        messagebox.showinfo("Saved", "Settings saved.")

    def import_internal_csv(self):
        filepath = filedialog.askopenfilename(filetypes=[("CSV", "*.csv")]); 
        if filepath: 
            try: 
                with open(filepath, 'r', encoding='utf-8-sig') as f: csv.DictReader(f); self.refresh_table()
            except: pass
    def export_table_csv(self): 
        filepath = filedialog.asksaveasfilename(defaultextension=".csv")
        if filepath:
            try:
                with open(filepath, 'w', newline='') as f:
                    writer = csv.writer(f); writer.writerow(["Name", "ID", "Team", "Active", "Load"])
                    for m in self.data['members']: writer.writerow([m['name'], m['id'], m['team'], m['active'], m['count']])
                messagebox.showinfo("Success", "Exported")
            except: pass

if __name__ == "__main__":
    app = H1ManagerApp()
    app.mainloop()
