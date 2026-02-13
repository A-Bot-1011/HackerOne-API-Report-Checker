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

# DEFAULT DATA
DEFAULT_DATA = {
    "api_id": "",          
    "api_token": "",       
    "program_handle": "",
    "use_hai": False,
    "members": [], 
    "history": []
}

class H1ManagerApp(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("HackerOne Manager V15 - Auto Sync Users")
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
            try:
                with open(CONFIG_FILE, 'r') as f:
                    d = json.load(f)
                    if "history" not in d: d["history"] = []
                    if "use_hai" not in d: d["use_hai"] = False
                    if "members" not in d: d["members"] = []
                    return d
            except:
                return DEFAULT_DATA

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

        # --- MANUAL OVERRIDE DEBUGGER ---
        debug_frame = ttk.LabelFrame(self.tab_dashboard, text="🛠️ Manual Override (Test Assignment)", padding=10)
        debug_frame.pack(fill='x', padx=10, pady=5)

        ttk.Label(debug_frame, text="Report ID:").pack(side='left', padx=5)
        self.ent_debug_rid = ttk.Entry(debug_frame, width=15)
        self.ent_debug_rid.pack(side='left', padx=5)

        ttk.Label(debug_frame, text="User ID (Numeric):").pack(side='left', padx=5)
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

    def force_assign_debug(self):
        rid = self.ent_debug_rid.get().strip()
        user_input = self.ent_debug_uid.get().strip()
        
        if not rid or not user_input:
            messagebox.showerror("Error", "Enter both Report ID and User ID")
            return
            
        self.log(f"🛠️ FORCING ASSIGNMENT: Report #{rid} -> User '{user_input}'")
        
        try:
            if self.assign_api_call(rid, user_input):
                self.log("✅ Force Assignment Successful.")
                # We ALSO post the comment on manual force
                self.post_public_comment(rid)
                
                found = False
                for m in self.data['members']:
                    if str(m['id']) == user_input:
                        m['count'] += 1
                        found = True
                if found:
                    self.save_data()
                    self.refresh_table()
            else:
                self.log("❌ Force Assignment FAILED. Check log.")
        except Exception as e:
            self.log(f"🔥 CRITICAL ERROR: {e}")
            traceback.print_exc()

    # --- HAI AI LOGIC ---
    def ask_hai_category(self, report_id):
        self.log(f"      🧠 Asking Hai to categorize Report #{report_id}...")
        
        url_create = "https://api.hackerone.com/v1/hai/chat/completions"
        prompt = (
            "Analyze the report context linked to this request. "
            "Categorize this report into exactly one of these three teams: 'WEB', 'MOBILE', or 'IOT'. "
            "Reply with ONLY the single word category name. Do not add punctuation."
        )

        try:
            r_id = int(report_id)
        except:
            self.log("      ❌ Error: Report ID must be an integer for Hai.")
            return None

        # 1. CREATE JOB
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
            resp = requests.post(
                url_create, 
                json=payload, 
                auth=HTTPBasicAuth(self.data['api_id'], self.data['api_token']),
                headers={"Content-Type": "application/json", "Accept": "application/json"}
            )
            
            if resp.status_code not in [200, 201]:
                self.log(f"      ❌ Hai Request Failed: {resp.status_code}")
                return None

            r_json = resp.json()
            if isinstance(r_json['data'], list): job_data = r_json['data'][0]
            else: job_data = r_json['data']
            
            job_id = job_data['id']
            self.log(f"      ⏳ Hai Job {job_id} Created. Polling...")

            # 2. POLL
            for i in range(10):
                time.sleep(2) 
                check_url = f"https://api.hackerone.com/v1/hai/chat/completions/{job_id}"
                check = requests.get(
                    check_url,
                    auth=HTTPBasicAuth(self.data['api_id'], self.data['api_token']),
                    headers={"Accept": "application/json"}
                )
                
                if check.status_code == 200:
                    c_json = check.json()
                    if isinstance(c_json['data'], list): attrs = c_json['data'][0]['attributes']
                    else: attrs = c_json['data']['attributes']
                    
                    state = attrs.get('state')
                    if state in ['completed', 'success']:
                        answer = attrs.get('response', '').strip().upper()
                        answer = answer.replace('.', '').replace("'", "").replace('"', "")
                        
                        if "WEB" in answer: return "web"
                        if "MOBILE" in answer: return "mobile"
                        if "IOT" in answer: return "iot"
                        
                        self.log(f"      ❓ Hai returned unknown category: {answer}")
                        return "web" 
                        
                    elif state == 'failed':
                        self.log("      ❌ Hai Analysis Failed.")
                        return None
            self.log("      ❌ Hai Timed Out.")
            return None

        except Exception as e:
            self.log(f"      ❌ Hai Exception: {e}")
            return None

    # --- AUTO COMMENT FUNCTION ---
    def post_public_comment(self, report_id):
        self.log(f"   💬 Posting public comment to Report #{report_id}...")
        url = f"https://api.hackerone.com/v1/reports/{report_id}/activities"
        
        message_text = (
            "Thank you for bringing this to our attention. "
            "We have received your report and are now validating the issue internally. "
            "We will get back to you soon."
        )

        payload = {
            "data": {
                "type": "activity-comment",
                "attributes": {
                    "message": message_text,
                    "internal": False 
                }
            }
        }

        try:
            r = requests.post(
                url, 
                json=payload,
                auth=HTTPBasicAuth(self.data['api_id'], self.data['api_token']),
                headers={"Content-Type": "application/json", "Accept": "application/json"}
            )
            if r.status_code in [200, 201]:
                self.log("   ✅ Comment Posted Successfully.")
            else:
                self.log(f"   ⚠️ Comment Failed ({r.status_code}): {r.text}")
        except Exception as e:
            self.log(f"   ⚠️ Comment Error: {e}")

    # --- TAB 2: USER MANAGEMENT ---
    def setup_team_management(self):
        main_frame = ttk.Frame(self.tab_teams)
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)

        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill='x', pady=(0, 5))
        
        # --- NEW SYNC BUTTON ---
        ttk.Button(btn_frame, text="🔄 Sync Users from H1", command=self.sync_h1_users_thread).pack(side='left', padx=2)
        
        ttk.Button(btn_frame, text="📂 Import CSV", command=self.import_internal_csv).pack(side='left', padx=2)
        ttk.Button(btn_frame, text="📤 Export Table", command=self.export_table_csv).pack(side='left', padx=20)
        
        filter_frame = ttk.Frame(main_frame); filter_frame.pack(fill='x', pady=(0, 10))
        ttk.Label(filter_frame, text="Filter View:").pack(side='left', padx=5)
        self.combo_filter = ttk.Combobox(filter_frame, values=["All Users", "Web Team", "Mobile Team", "IoT Team", "N/A", "Missing H1 ID"], state="readonly", width=20)
        self.combo_filter.current(0); self.combo_filter.pack(side='left', padx=5); self.combo_filter.bind("<<ComboboxSelected>>", self.apply_filter)
        
        ttk.Button(filter_frame, text="+ Manual Add", command=self.add_new_member).pack(side='right', padx=2)
        ttk.Button(filter_frame, text="✏️ Edit User", command=self.edit_current_user_popup).pack(side='right', padx=2)
        ttk.Button(btn_frame, text="🗑️ Delete Selected", command=self.mass_delete).pack(side='right', padx=2)

        columns = ("active", "h1_name", "email", "team", "role", "load", "h1_id")
        self.tree = ttk.Treeview(main_frame, columns=columns, show='headings', selectmode='extended')
        for c in columns: self.tree.heading(c, text=c.title(), command=lambda _c=c: self.sort_tree(_c))
        self.tree.column("active", width=60, anchor='center'); self.tree.column("h1_name", width=150)
        self.tree.column("email", width=200); self.tree.column("team", width=80)
        self.tree.column("role", width=100); self.tree.column("load", width=50, anchor='center'); self.tree.column("h1_id", width=80)

        scrollbar = ttk.Scrollbar(main_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        self.tree.pack(side='left', fill='both', expand=True); scrollbar.pack(side='right', fill='y')
        self.tree.bind("<Double-1>", self.edit_current_user_popup)

        edit_frame = ttk.LabelFrame(main_frame, text="Batch Action", padding=10); edit_frame.pack(side='bottom', fill='x', pady=(10, 0))
        ttk.Label(edit_frame, text="Set Team:").pack(side='left', padx=5); self.combo_team = ttk.Combobox(edit_frame, values=["N/A", "web", "mobile", "iot"], state="readonly", width=15); self.combo_team.pack(side='left', padx=5)
        ttk.Label(edit_frame, text="Set Active:").pack(side='left', padx=(20, 5)); self.var_active_edit = tk.BooleanVar(); ttk.Checkbutton(edit_frame, variable=self.var_active_edit).pack(side='left')
        ttk.Button(edit_frame, text="Apply Batch", command=self.save_batch_edit).pack(side='right', padx=20)
        self.refresh_table()

    # --- NEW: SYNC USERS LOGIC ---
    def sync_h1_users_thread(self):
        threading.Thread(target=self.sync_h1_users, daemon=True).start()

    def sync_h1_users(self):
        self.log("🔄 Starting User Sync...")
        
        if not self.data['api_id'] or not self.data['api_token']:
            self.log("❌ Error: Missing API Credentials.")
            return

        auth = HTTPBasicAuth(self.data['api_id'], self.data['api_token'])
        
        # Step 1: Get Organization ID
        try:
            self.log("   1. Fetching Organization ID...")
            r_org = requests.get('https://api.hackerone.com/v1/me/organizations', auth=auth, headers={'Accept': 'application/json'})
            if r_org.status_code != 200:
                self.log(f"   ❌ Failed to get Org ID: {r_org.status_code}")
                return
            
            orgs = r_org.json().get('data', [])
            if not orgs:
                self.log("   ❌ No organizations found.")
                return
            
            # Use the first organization found
            org_id = orgs[0]['id']
            org_name = orgs[0]['attributes'].get('handle', 'Unknown')
            self.log(f"   ✅ Found Org: {org_name} (ID: {org_id})")

        except Exception as e:
            self.log(f"   ❌ Network Error: {e}")
            return

        # Step 2: Fetch Members
        self.log("   2. Fetching Members...")
        members_url = f"https://api.hackerone.com/v1/organizations/{org_id}/members"
        
        new_count = 0
        update_count = 0
        
        try:
            # Handle Pagination loop
            while members_url:
                r_mem = requests.get(members_url, auth=auth, headers={'Accept': 'application/json'})
                if r_mem.status_code != 200:
                    self.log(f"   ❌ Error fetching members: {r_mem.status_code}")
                    break
                
                data = r_mem.json()
                member_list = data.get('data', [])
                
                for m in member_list:
                    attrs = m.get('attributes', {})
                    
                    # API Data
                    h1_username = attrs.get('username')
                    h1_email = attrs.get('email')
                    h1_user_id = attrs.get('user_id') # Crucial for assignment
                    
                    if not h1_username: continue

                    # Check if user exists in local DB
                    existing = next((x for x in self.data['members'] if x['name'] == h1_username), None)
                    
                    if existing:
                        # Update existing
                        if existing['id'] != str(h1_user_id) or existing.get('email') != h1_email:
                            existing['id'] = str(h1_user_id)
                            existing['email'] = h1_email
                            update_count += 1
                    else:
                        # Create new
                        new_member = {
                            "name": h1_username,
                            "email": h1_email,
                            "id": str(h1_user_id),
                            "team": "N/A", # User must manually set team later
                            "role": "Member",
                            "active": True,
                            "count": 0
                        }
                        self.data['members'].append(new_member)
                        new_count += 1
                
                # Check for next page
                links = data.get('links', {})
                members_url = links.get('next') # Will be None if no more pages

            self.save_data()
            self.after(0, self.refresh_table) # Update UI safely
            self.log(f"   ✅ Sync Complete: {new_count} new, {update_count} updated.")
            messagebox.showinfo("Sync Complete", f"Found {new_count} new users.\nUpdated {update_count} existing users.\n\nPlease assign Teams manually.")

        except Exception as e:
            self.log(f"   ❌ Sync Error: {e}")
            traceback.print_exc()

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
        ttk.Label(f, text="Email:").pack(anchor='w'); e_real = ttk.Entry(f); e_real.insert(0, member.get('email', '')); e_real.pack(fill='x', pady=5)
        ttk.Label(f, text="Team:").pack(anchor='w'); e_team = ttk.Combobox(f, values=["N/A", "web", "mobile", "iot"], state="readonly"); e_team.set(member['team']); e_team.pack(fill='x', pady=5)
        ttk.Label(f, text="Role:").pack(anchor='w'); e_role = ttk.Entry(f); e_role.insert(0, member.get('role', '')); e_role.pack(fill='x', pady=5)
        ttk.Label(f, text="Load:").pack(anchor='w'); e_load = ttk.Spinbox(f, from_=0, to=999); e_load.set(member['count']); e_load.pack(fill='x', pady=5)
        var_active = tk.BooleanVar(value=member['active']); ttk.Checkbutton(f, text="Active", variable=var_active).pack(anchor='w', pady=10)

        def save_and_close():
            member['name'] = e_name.get(); member['id'] = e_id.get().strip(); member['email'] = e_real.get()
            member['team'] = e_team.get(); member['role'] = e_role.get(); member['count'] = int(e_load.get())
            member['active'] = var_active.get(); self.save_data(); self.refresh_table(); top.destroy()
        ttk.Button(f, text="💾 Save", command=save_and_close).pack(fill='x', pady=20)

    # --- LOGIC: IMPORTS/EXPORTS/TABLE ---
    def import_internal_csv(self):
        # Placeholder for CSV import if needed
        pass

    def import_h1_ids(self):
        # Placeholder
        pass

    def export_table_csv(self):
        filepath = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
        if not filepath: return
        try:
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f); writer.writerow(["Active", "Nickname", "Email", "Team", "Role", "Load", "H1 ID"])
                for m in self.data['members']: writer.writerow([m['active'], m['name'], m.get('email',''), m['team'], m.get('role',''), m['count'], m['id']])
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
            self.tree.insert("", "end", values=(status, m['name'], m.get('email', '-'), m['team'].upper(), m.get('role', '-'), m['count'], h1_id))

    def save_batch_edit(self):
        selected = self.tree.selection(); new_team = self.combo_team.get(); new_active = self.var_active_edit.get()
        for item_id in selected:
            h1_name = self.tree.item(item_id)['values'][1]
            for m in self.data['members']:
                if m['name'] == h1_name: m['team'] = new_team; m['active'] = new_active
        self.save_data(); self.refresh_table()

    def mass_delete(self):
        selected = self.tree.selection()
        if not selected or not messagebox.askyesno("Confirm", "Delete selected?"): return
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

    # --- SETTINGS & SCANNING ---
    def save_settings_ui(self):
        self.data['api_id'] = self.ent_api_id.get()
        self.data['api_token'] = self.ent_api_token.get()
        self.data['program_handle'] = self.ent_program.get()
        self.save_data()
        messagebox.showinfo("Saved", "Settings saved.")

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
        if not self.data['api_id'] or not self.data['api_token']:
            self.log("❌ Error: Credentials missing in Settings.")
            self.reset_scan_btn()
            return

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
                if ai_choice != team_type:
                    self.log(f"      ⚠️ Hai Override! Regular: {team_type.upper()} -> Hai: {ai_choice.upper()}")
                    team_type = ai_choice
                else:
                    self.log(f"      ✅ Hai Confirmed: {ai_choice.upper()}")
        
        self.log(f"   ➤ Final Category: {team_type.upper()}")

        # Ensure we only pick members who have a Valid ID
        eligible = [m for m in self.data['members'] if m['team'] == team_type and m['active'] and m['id'] and m['id'] != "0"]
        
        if not eligible: self.log(f"   ❌ No active members with valid IDs for {team_type}."); return

        best = sorted(eligible, key=lambda x: x['count'])[0]
        self.log(f"   ➤ Assigning to {best['name']}")

        # We pass the ID directly now
        if self.assign_api_call(r_id, best['id']):
            # --- SUCCESS! POST COMMENT AND SAVE ---
            self.post_public_comment(r_id)
            
            best['count'] += 1
            self.data['history'].append({"date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "report_id": r_id, "assignee": best['name'], "team": team_type})
            self.save_data()
            self.refresh_table()
            self.log(f"   ✅ Assigned.")

    # --- API CALL (PUT METHOD) ---
    def assign_api_call(self, report_id, user_input):
        user_input = str(user_input).strip()
        r_id = str(report_id)

        self.log(f"   🚀 Assigning Report #{r_id}...")

        if not user_input.isdigit():
             self.log("   ❌ Error: The API requires a Numeric User ID for this endpoint.")
             return False
        
        url = f"https://api.hackerone.com/v1/reports/{r_id}/assignee"
        
        payload = {
            "data": {
                "type": "user",
                "id": int(user_input)
            }
        }
        
        try:
            if not self.data['api_id'] or not self.data['api_token']:
                self.log("❌ Error: Missing Credentials.")
                return False

            r = requests.put(
                url, 
                json=payload,
                auth=HTTPBasicAuth(self.data['api_id'], self.data['api_token']),
                headers={"Content-Type": "application/json", "Accept": "application/json"}
            )

            if r.status_code == 200: 
                self.log("   ✅ Assignment Success!")
                return True

            self.log(f"   ❌ Failed. Status: {r.status_code}")
            self.log(f"   📝 Response: {r.text}")
            return False

        except Exception as e:
            self.log(f"   ❌ API Crash: {e}")
            traceback.print_exc()
            return False

if __name__ == "__main__":
    app = H1ManagerApp()
    app.mainloop()
