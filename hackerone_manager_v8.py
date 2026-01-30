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

DEFAULT_DATA = {
    "api_id": "",
    "api_token": "",
    "program_handle": "xiaomi",
    "use_hai": False,
    "members": [], 
    "history": []
}

class H1ManagerApp(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("HackerOne Manager V8 - Assignment Debugger")
        self.geometry("1250x900")
        
        self.data = self.load_data()
        self.is_scanning = False
        self.sort_col = None
        self.sort_reverse = False
        self.current_filter = "All"
        
        # --- UI LAYOUT ---
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(expand=True, fill='both', padx=10, pady=10)

        # Tab 1: Dashboard
        self.tab_dashboard = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_dashboard, text="🤖 Dashboard")
        self.setup_dashboard()

        # Tab 2: User Table
        self.tab_teams = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_teams, text="👥 User Database")
        self.setup_team_management()

        # Tab 3: Settings
        self.tab_settings = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_settings, text="⚙️ Settings")
        self.setup_settings()

    # --- DATA HANDLING ---
    def load_data(self):
        if not os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'w') as f:
                json.dump(DEFAULT_DATA, f, indent=4)
            return DEFAULT_DATA
        else:
            with open(CONFIG_FILE, 'r') as f:
                d = json.load(f)
                if "history" not in d: d["history"] = []
                if "use_hai" not in d: d["use_hai"] = False
                for m in d.get('members', []):
                    if m.get('team') == "Unassigned": m['team'] = "N/A"
                return d

    def save_data(self):
        with open(CONFIG_FILE, 'w') as f:
            json.dump(self.data, f, indent=4)

    # --- TAB 1: DASHBOARD ---
    def setup_dashboard(self):
        # Scan Controls
        scan_frame = ttk.LabelFrame(self.tab_dashboard, text="Scanner Controls", padding=10)
        scan_frame.pack(fill='x', padx=10, pady=5)

        self.btn_scan = ttk.Button(scan_frame, text="⚡ Scan New Reports", command=self.run_scan_thread)
        self.btn_scan.pack(side='left', padx=5)

        self.var_auto = tk.BooleanVar(value=False)
        self.chk_auto = ttk.Checkbutton(scan_frame, text="Auto-Scan (60s)", variable=self.var_auto, command=self.toggle_auto)
        self.chk_auto.pack(side='left', padx=15)
        
        self.var_hai = tk.BooleanVar(value=self.data.get('use_hai', False))
        self.chk_hai = ttk.Checkbutton(scan_frame, text="🧠 Enable Hai (AI)", variable=self.var_hai, command=self.save_ai_toggle)
        self.chk_hai.pack(side='left', padx=15)

        # --- NEW: MANUAL OVERRIDE DEBUGGER ---
        debug_frame = ttk.LabelFrame(self.tab_dashboard, text="🛠️ Manual Override (Test Assignment)", padding=10)
        debug_frame.pack(fill='x', padx=10, pady=5)

        ttk.Label(debug_frame, text="Report ID:").pack(side='left', padx=5)
        self.ent_debug_rid = ttk.Entry(debug_frame, width=15)
        self.ent_debug_rid.pack(side='left', padx=5)

        ttk.Label(debug_frame, text="User ID:").pack(side='left', padx=5)
        self.ent_debug_uid = ttk.Entry(debug_frame, width=15)
        self.ent_debug_uid.pack(side='left', padx=5)

        ttk.Button(debug_frame, text="🚀 Force Assign", command=self.force_assign_debug).pack(side='left', padx=20)
        
        ttk.Button(scan_frame, text="📜 History", command=self.show_history_window).pack(side='right', padx=5)

        # Log Window
        log_frame = ttk.LabelFrame(self.tab_dashboard, text="Activity Log", padding=10)
        log_frame.pack(expand=True, fill='both', padx=10, pady=5)

        self.log_box = scrolledtext.ScrolledText(log_frame, height=15, state='disabled')
        self.log_box.pack(expand=True, fill='both')

    def log(self, message):
        self.log_box.config(state='normal')
        self.log_box.insert(tk.END, f"{message}\n")
        self.log_box.see(tk.END)
        self.log_box.config(state='disabled')

    def save_ai_toggle(self):
        self.data['use_hai'] = self.var_hai.get()
        self.save_data()

    # --- MANUAL ASSIGN DEBUGGER ---
    def force_assign_debug(self):
        rid = self.ent_debug_rid.get().strip()
        uid = self.ent_debug_uid.get().strip()
        
        if not rid or not uid:
            messagebox.showerror("Error", "Enter both IDs")
            return
            
        self.log(f"🛠️ FORCING ASSIGNMENT: Report #{rid} -> User {uid}")
        
        # Call the assignment function but handle UI updates manually here
        success = self.assign_api_call(rid, uid)
        
        if success:
            self.log("✅ Force Assignment Successful.")
            # Update internal counter if user exists in DB
            for m in self.data['members']:
                if str(m['id']) == str(uid):
                    m['count'] += 1
                    self.save_data()
                    self.refresh_table()
                    self.log(f"   Updated load for {m['name']} to {m['count']}")
        else:
            self.log("❌ Force Assignment FAILED. Check log for API response.")

    # --- HAI AI LOGIC (INFRASTRUCTURE OVERRIDE) ---
    def ask_hai_category(self, report_id):
        url_create = "https://api.hackerone.com/v1/hai/chat/completions"
        prompt = (
            "You are a Senior Security Architect. Route this report to: 'WEB', 'MOBILE', or 'IOT'.\n\n"
            "🚨 CRITICAL OVERRIDE: Ignore the 'Asset Type' label (e.g., AndroidApk) if the technical evidence shows a Server-Side issue.\n\n"
            "1. WEB (Backend Infrastructure): \n"
            "   - ANY issue involving Server Software: Apache Tomcat, Nginx, IIS, OpenSSL, HAProxy.\n"
            "   - ANY issue on Backend APIs/Gateways: 'api.*', 'push.*', 'register.*', 'gateway.*'.\n"
            "   - Vulnerabilities: HTTP Request Smuggling, Server Version Disclosure, SQLi, SSRF.\n"
            "   - LOGIC: If the fix requires updating a Server, it is WEB.\n\n"
            "2. MOBILE (Client Binary):\n"
            "   - Issues residing strictly inside the .APK or .IPA file.\n"
            "   - Examples: Hardcoded API keys in strings.xml, Insecure Data Storage on SD Card, Deeplink Logic Errors.\n"
            "   - LOGIC: If the fix requires releasing an App Store update, it is MOBILE.\n\n"
            "3. IOT (Hardware/Firmware):\n"
            "   - Physical devices, Firmware (.bin), MQTT, RTSP, Serial Console.\n\n"
            "SPECIFIC EXAMPLE: An 'Apache Tomcat' vulnerability on 'xmpush.xiaomi.com' is WEB (Server Infra), NOT Mobile.\n"
            "Classify based on the Technology Stack (Server vs Client). Reply with ONE word."
        )

        try:
            r_id = int(report_id)
        except:
            return None

        payload = {
            "data": {
                "type": "completion-request",
                "attributes": {
                    "messages": [{"role": "user", "content": prompt}],
                    "report_ids": [r_id]
                }
            }
        }

        try:
            self.log(f"      📡 Sending Data to Hai (Infra Mode)...")
            resp = requests.post(
                url_create, 
                json=payload, 
                auth=HTTPBasicAuth(self.data['api_id'], self.data['api_token']),
                headers={"Content-Type": "application/json", "Accept": "application/json"}
            )
            
            if resp.status_code not in [200, 201]:
                self.log(f"      ❌ Hai Status: {resp.status_code}")
                return None

            r_json = resp.json()
            if isinstance(r_json['data'], list):
                job_id = r_json['data'][0]['id']
            else:
                job_id = r_json['data']['id']

            self.log(f"      ⏳ Hai Analyzing (Job {job_id})...")
            
            for i in range(10):
                time.sleep(2) 
                check = requests.get(
                    f"https://api.hackerone.com/v1/hai/chat/completions/{job_id}",
                    auth=HTTPBasicAuth(self.data['api_id'], self.data['api_token']),
                    headers={"Accept": "application/json"}
                )
                
                if check.status_code == 200:
                    c_json = check.json()
                    if isinstance(c_json['data'], list):
                        attrs = c_json['data'][0]['attributes']
                    else:
                        attrs = c_json['data']['attributes']
                    
                    state = attrs.get('state')
                    if state in ['created', 'completed']:
                        answer = attrs.get('response', '').strip().upper()
                        return answer.replace('.', '').replace("'", "")
                    elif state == 'failed':
                        return None
            return None
        except Exception as e:
            self.log(f"      ❌ Hai Error: {e}")
            return None

    # --- TAB 2: USER MANAGEMENT ---
    def setup_team_management(self):
        main_frame = ttk.Frame(self.tab_teams)
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)

        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill='x', pady=(0, 5))
        ttk.Button(btn_frame, text="1. 📂 Import Master CSV", command=self.import_internal_csv).pack(side='left', padx=2)
        ttk.Button(btn_frame, text="2. 🔗 Sync H1 IDs", command=self.import_h1_ids).pack(side='left', padx=2)
        ttk.Button(btn_frame, text="📤 Export Table", command=self.export_table_csv).pack(side='left', padx=20)
        
        filter_frame = ttk.Frame(main_frame); filter_frame.pack(fill='x', pady=(0, 10))
        ttk.Label(filter_frame, text="Filter View:").pack(side='left', padx=5)
        self.combo_filter = ttk.Combobox(filter_frame, values=["All Users", "Web Team", "Mobile Team", "IoT Team", "N/A", "Missing H1 ID"], state="readonly", width=20)
        self.combo_filter.current(0); self.combo_filter.pack(side='left', padx=5); self.combo_filter.bind("<<ComboboxSelected>>", self.apply_filter)
        
        ttk.Button(filter_frame, text="+ Manual Add", command=self.add_new_member).pack(side='right', padx=2)
        ttk.Button(filter_frame, text="✏️ Edit User", command=self.edit_current_user_popup).pack(side='right', padx=2)
        ttk.Button(btn_frame, text="🗑️ Delete Selected", command=self.mass_delete).pack(side='right', padx=2)

        columns = ("active", "h1_name", "real_name", "team", "role", "load", "h1_id")
        self.tree = ttk.Treeview(main_frame, columns=columns, show='headings', selectmode='extended')
        for c in columns: self.tree.heading(c, text=c.title(), command=lambda _c=c: self.sort_tree(_c))
        self.tree.column("active", width=60, anchor='center'); self.tree.column("h1_name", width=150)
        self.tree.column("real_name", width=100); self.tree.column("team", width=80)
        self.tree.column("role", width=200); self.tree.column("load", width=50, anchor='center'); self.tree.column("h1_id", width=80)

        scrollbar = ttk.Scrollbar(main_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        self.tree.pack(side='left', fill='both', expand=True); scrollbar.pack(side='right', fill='y')
        self.tree.bind("<Double-1>", self.edit_current_user_popup)

        edit_frame = ttk.LabelFrame(main_frame, text="Batch Action", padding=10); edit_frame.pack(side='bottom', fill='x', pady=(10, 0))
        ttk.Label(edit_frame, text="Set Team:").pack(side='left', padx=5); self.combo_team = ttk.Combobox(edit_frame, values=["N/A", "web", "mobile", "iot"], state="readonly", width=15); self.combo_team.pack(side='left', padx=5)
        ttk.Label(edit_frame, text="Set Active:").pack(side='left', padx=(20, 5)); self.var_active_edit = tk.BooleanVar(); ttk.Checkbutton(edit_frame, variable=self.var_active_edit).pack(side='left')
        ttk.Button(edit_frame, text="Apply Batch", command=self.save_batch_edit).pack(side='right', padx=20)
        self.refresh_table()

    def edit_current_user_popup(self, event=None):
        selected = self.tree.selection()
        if not selected: return
        h1_name = self.tree.item(selected[0])['values'][1]
        member = next((m for m in self.data['members'] if m['name'] == h1_name), None)
        if not member: return

        top = tk.Toplevel(self); top.title(f"Edit: {h1_name}"); top.geometry("400x450")
        f = ttk.Frame(top, padding=20); f.pack(fill='both', expand=True)
        ttk.Label(f, text="Nickname:").pack(anchor='w'); e_name = ttk.Entry(f); e_name.insert(0, member['name']); e_name.pack(fill='x', pady=5)
        ttk.Label(f, text="H1 ID:").pack(anchor='w'); e_id = ttk.Entry(f); e_id.insert(0, member['id']); e_id.pack(fill='x', pady=5)
        ttk.Label(f, text="Real Name:").pack(anchor='w'); e_real = ttk.Entry(f); e_real.insert(0, member.get('real_name', '')); e_real.pack(fill='x', pady=5)
        ttk.Label(f, text="Team:").pack(anchor='w'); e_team = ttk.Combobox(f, values=["N/A", "web", "mobile", "iot"], state="readonly"); e_team.set(member['team']); e_team.pack(fill='x', pady=5)
        ttk.Label(f, text="Role:").pack(anchor='w'); e_role = ttk.Entry(f); e_role.insert(0, member.get('role', '')); e_role.pack(fill='x', pady=5)
        ttk.Label(f, text="Load:").pack(anchor='w'); e_load = ttk.Spinbox(f, from_=0, to=999); e_load.set(member['count']); e_load.pack(fill='x', pady=5)
        var_active = tk.BooleanVar(value=member['active']); ttk.Checkbutton(f, text="Active", variable=var_active).pack(anchor='w', pady=10)

        def save_and_close():
            member['name'] = e_name.get(); member['id'] = e_id.get().strip(); member['real_name'] = e_real.get()
            member['team'] = e_team.get(); member['role'] = e_role.get(); member['count'] = int(e_load.get())
            member['active'] = var_active.get(); self.save_data(); self.refresh_table(); top.destroy()
        ttk.Button(f, text="💾 Save", command=save_and_close).pack(fill='x', pady=20)

    # --- LOGIC: IMPORTS/EXPORTS/TABLE ---
    def import_internal_csv(self):
        filepath = filedialog.askopenfilename(filetypes=[("CSV", "*.csv"), ("All", "*.*")])
        if not filepath: return
        if not messagebox.askyesno("Confirm", "Overwrite list?"): return
        try:
            new_members = []
            with open(filepath, 'r', encoding='utf-8-sig', errors='replace') as f:
                reader = csv.DictReader(f); reader.fieldnames = [str(n).strip() for n in reader.fieldnames]
                for row in reader:
                    nick = row.get('昵称') or row.get('username') or row.get('User Name')
                    if not nick: continue
                    role = row.get('权限') or row.get('role') or ""
                    team = "N/A"
                    role_u = role.upper()
                    if "WEB" in role_u: team = "web"
                    elif "IOT" in role_u or "硬件" in role_u: team = "iot"
                    elif "APP" in role_u or "MOBILE" in role_u: team = "mobile"
                    new_members.append({"name": nick.strip(), "real_name": row.get('name') or row.get('姓名') or "", "role": role, "team": team, "id": "", "active": True, "count": 0})
            self.data['members'] = new_members; self.save_data(); self.refresh_table()
            messagebox.showinfo("Success", f"Imported {len(new_members)} users.")
        except Exception as e: messagebox.showerror("Error", str(e))

    def import_h1_ids(self):
        filepath = filedialog.askopenfilename(filetypes=[("CSV", "*.csv")])
        if not filepath: return
        try:
            matched = 0
            with open(filepath, 'r', encoding='utf-8-sig') as f:
                reader = csv.DictReader(f); reader.fieldnames = [str(n).strip() for n in reader.fieldnames]
                if 'user_id' not in reader.fieldnames: messagebox.showerror("Error", "Need 'user_id'"); return
                for row in reader:
                    for m in self.data['members']:
                        if m['name'] == row.get('username'): m['id'] = row.get('user_id'); matched += 1
            self.save_data(); self.refresh_table(); messagebox.showinfo("Success", f"Synced IDs for {matched} users.")
        except Exception as e: messagebox.showerror("Error", str(e))

    def export_table_csv(self):
        filepath = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
        if not filepath: return
        try:
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f); writer.writerow(["Active", "Nickname", "Real Name", "Team", "Role", "Load", "H1 ID"])
                for m in self.data['members']: writer.writerow([m['active'], m['name'], m.get('real_name',''), m['team'], m.get('role',''), m['count'], m['id']])
            messagebox.showinfo("Success", "Exported.")
        except Exception as e: messagebox.showerror("Error", str(e))

    def sort_tree(self, col):
        if self.sort_col == col: self.sort_reverse = not self.sort_reverse
        else: self.sort_reverse = False; self.sort_col = col
        self.data['members'].sort(key=lambda x: str(x.get(col, '')).lower(), reverse=self.sort_reverse)
        self.refresh_table()

    def apply_filter(self, event=None):
        self.current_filter = self.combo_filter.get(); self.refresh_table()

    def refresh_table(self):
        for item in self.tree.get_children(): self.tree.delete(item)
        for m in self.data['members']:
            if self.current_filter == "Web Team" and m['team'] != "web": continue
            if self.current_filter == "Mobile Team" and m['team'] != "mobile": continue
            if self.current_filter == "IoT Team" and m['team'] != "iot": continue
            if self.current_filter == "N/A" and m['team'] != "N/A": continue
            if self.current_filter == "Missing H1 ID" and (m['id'] == "" or m['id'] == "0"): continue
            status = "✅" if m['active'] else "❌"; h1_id = "⚠️ MISSING" if (m['id'] == "" or m['id'] == "0") else m['id']
            self.tree.insert("", "end", values=(status, m['name'], m.get('real_name', '-'), m['team'].upper(), m.get('role', '-'), m['count'], h1_id))

    def save_batch_edit(self):
        selected = self.tree.selection(); new_team = self.combo_team.get(); new_active = self.var_active_edit.get()
        for item_id in selected:
            h1_name = self.tree.item(item_id)['values'][1]
            for m in self.data['members']:
                if m['name'] == h1_name: m['team'] = new_team; m['active'] = new_active
        self.save_data(); self.refresh_table()

    def mass_delete(self):
        selected = self.tree.selection()
        if not selected or not messagebox.askyesno("Confirm", "Delete?"): return
        names = [self.tree.item(i)['values'][1] for i in selected]
        self.data['members'] = [m for m in self.data['members'] if m['name'] not in names]
        self.save_data(); self.refresh_table()

    def add_new_member(self):
        self.data['members'].insert(0, {"name": "New", "id": "", "team": "N/A", "active": True, "count": 0})
        self.save_data(); self.refresh_table()

    def show_history_window(self):
        top = tk.Toplevel(self); top.title("History"); top.geometry("600x400")
        txt = scrolledtext.ScrolledText(top); txt.pack(fill='both', expand=True)
        for i in reversed(self.data.get('history', [])): txt.insert(tk.END, f"[{i['date']}] Report #{i['report_id']} -> {i['assignee']} ({i['team']})\n")

    # --- SCANNING & ASSIGNMENT ---
    def save_settings_ui(self):
        self.data['api_id'] = self.ent_api_id.get(); self.data['api_token'] = self.ent_api_token.get(); self.data['program_handle'] = self.ent_program.get()
        self.save_data(); messagebox.showinfo("Saved", "Settings saved.")

    def setup_settings(self):
        f = ttk.Frame(self.tab_settings, padding=20); f.pack(fill='both')
        ttk.Label(f, text="API Identifier:").pack(anchor='w'); self.ent_api_id = ttk.Entry(f, width=50); self.ent_api_id.insert(0, self.data['api_id']); self.ent_api_id.pack(anchor='w')
        ttk.Label(f, text="API Token:").pack(anchor='w'); self.ent_api_token = ttk.Entry(f, width=50, show="*"); self.ent_api_token.insert(0, self.data['api_token']); self.ent_api_token.pack(anchor='w')
        ttk.Label(f, text="Program Handle:").pack(anchor='w'); self.ent_program = ttk.Entry(f, width=50); self.ent_program.insert(0, self.data['program_handle']); self.ent_program.pack(anchor='w')
        ttk.Button(f, text="Save Settings", command=self.save_settings_ui).pack(pady=20)

    def run_scan_thread(self):
        if not self.is_scanning: self.is_scanning = True; self.btn_scan.config(state='disabled'); threading.Thread(target=self.perform_scan, daemon=True).start()

    def toggle_auto(self):
        if self.var_auto.get(): self.log("⏱️ Auto-Scan ON"); threading.Thread(target=self.auto_scan_loop, daemon=True).start()
        else: self.log("⏸️ Auto-Scan OFF")

    def auto_scan_loop(self):
        while self.var_auto.get():
            self.perform_scan(); 
            for _ in range(60): 
                if not self.var_auto.get(): break
                time.sleep(1)

    def perform_scan(self):
        self.log(f"🔍 Scanning {self.data['program_handle']}...")
        try:
            resp = requests.get("https://api.hackerone.com/v1/reports", 
                params={"filter[program][]": self.data['program_handle'], "filter[state][]": "new", "page[size]": 100},
                auth=HTTPBasicAuth(self.data['api_id'], self.data['api_token']), headers={"Accept": "application/json"})
            if resp.status_code != 200: self.log(f"❌ API Error: {resp.status_code}"); self.reset_scan_btn(); return
            
            unassigned = [r for r in resp.json().get('data', []) if r.get('relationships', {}).get('assignee', {}).get('data') is None]
            if unassigned: 
                self.log(f"🚨 Found {len(unassigned)} new reports!")
                for r in unassigned: self.process_report(r)
            else: self.log("✅ No unassigned reports.")
        except Exception as e: self.log(f"❌ Error: {e}")
        self.reset_scan_btn()

    def reset_scan_btn(self): self.is_scanning = False; self.btn_scan.config(state='normal')

    def process_report(self, report):
        r_id = report['id']
        scope = report.get('relationships', {}).get('structured_scope', {}).get('data', {})
        asset_type = scope.get('attributes', {}).get('asset_type', '').lower()
        asset_val = scope.get('attributes', {}).get('asset_identifier', '').lower()

        self.log(f"   ➤ [#{r_id}] Asset: {asset_val}")

        team_type = "web"
        if "google_play" in asset_type or "apple_store" in asset_type or "android" in asset_val: team_type = "mobile"
        elif "hardware" in asset_type or "firmware" in asset_val: team_type = "iot"
        
        if self.data.get('use_hai', False):
            ai_choice = self.ask_hai_category(r_id)
            if ai_choice:
                if "MOBILE" in ai_choice: ai_team = "mobile"
                elif "IOT" in ai_choice or "HARDWARE" in ai_choice: ai_team = "iot"
                elif "WEB" in ai_choice: ai_team = "web"
                else: ai_team = None

                if ai_team and ai_team != team_type:
                    self.log(f"      ⚠️ AI Disagreement! Bot: {team_type.upper()}, Hai: {ai_team.upper()}")
                    team_type = ai_team
                elif ai_team: self.log(f"      ✅ AI Confirmed: {ai_team.upper()}")
        
        self.log(f"   ➤ Final Category: {team_type.upper()}")

        # FILTER: Must have ID and be active
        eligible = [m for m in self.data['members'] if m['team'] == team_type and m['active'] and m['id'] and m['id'] != "0"]
        
        if not eligible: self.log(f"   ❌ No active members with valid IDs for {team_type}."); return

        best = sorted(eligible, key=lambda x: x['count'])[0]
        self.log(f"   ➤ Assigning to {best['name']}")

        if self.assign_api_call(r_id, best['id']):
            best['count'] += 1
            self.data['history'].append({"date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "report_id": r_id, "assignee": best['name'], "team": team_type})
            self.save_data(); self.refresh_table()
            self.log(f"   ✅ Assigned.")

    # --- UPDATED ASSIGNMENT LOGIC (DEBUG MODE) ---
    def assign_api_call(self, report_id, user_id):
        url = f"https://api.hackerone.com/v1/reports/{report_id}"
        
        # Ensure user_id is a string
        payload = {
            "data": {
                "type": "report",
                "relationships": {
                    "assignee": {
                        "data": {
                            "type": "user", 
                            "id": str(user_id) # Ensure String
                        }
                    }
                }
            }
        }
        
        try:
            r = requests.patch(
                url, 
                json=payload, 
                auth=HTTPBasicAuth(self.data['api_id'], self.data['api_token']),
                headers={"Content-Type": "application/json", "Accept": "application/json"}
            )
            
            # --- DEBUGGING: PRINT THE REAL REASON ---
            if r.status_code == 200:
                return True
            else:
                self.log(f"   ❌ Assignment API Failed (Status {r.status_code})")
                self.log(f"   📜 Details: {r.text}") # <--- THIS IS KEY
                return False
        except Exception as e:
            self.log(f"   ❌ API Crash: {e}")
            return False

if __name__ == "__main__":
    app = H1ManagerApp()
    app.mainloop()