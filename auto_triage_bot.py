import requests
from requests.auth import HTTPBasicAuth
import time
import msvcrt  # This allows us to detect key presses on Windows
import sys

# --- CONFIGURATION ---
API_ID = "" # <--- Update this!
API_TOKEN = ""  # <--- Update this!
PROGRAM_HANDLE = ""                 # <--- Update this!

# How many seconds to wait between automatic scans
SCAN_INTERVAL = 21600 

def check_new_reports():
    print(f"\n[ {time.strftime('%H:%M:%S')} ] 📡 Scanning inbox for '{PROGRAM_HANDLE}'...")

    url = "https://api.hackerone.com/v1/reports"
    params = {
        "filter[program][]": PROGRAM_HANDLE,
        "filter[state][]": "new",
        "page[size]": 100
    }

    try:
        response = requests.get(
            url,
            params=params,
            auth=HTTPBasicAuth(API_ID, API_TOKEN),
            headers={"Accept": "application/json"}
        )

        if response.status_code != 200:
            print(f"❌ API Error: {response.status_code} - {response.text}")
            return

        data = response.json().get('data', [])
        
        # Filter for strictly unassigned reports
        unassigned = [r for r in data if r.get('relationships', {}).get('assignee', {}).get('data') is None]
        count = len(unassigned)

        if count == 0:
            print("✅ No new reports found. Waiting...")
        else:
            print(f"🚨 FOUND {count} NEW REPORT(S)!")
            for report in unassigned:
                r_id = report['id']
                r_title = report['attributes']['title']
                print(f"   ➤ [#{r_id}] {r_title}")
                
                # THIS IS WHERE WE WILL ADD THE LOGIC LATER
                # process_report(report)

    except Exception as e:
        print(f"❌ Connection Error: {e}")

# --- MAIN LOOP ---
def main():
    print(f"🤖 Bot active for program: {PROGRAM_HANDLE}")
    print(f"⏱️  Auto-scan every {SCAN_INTERVAL} seconds.")
    print("⌨️  Press any key to FORCE a scan immediately.")
    print("------------------------------------------------")

    last_scan_time = 0

    while True:
        current_time = time.time()
        
        # Check 1: Is it time for an auto-scan?
        if current_time - last_scan_time > SCAN_INTERVAL:
            check_new_reports()
            last_scan_time = time.time()
        
        # Check 2: Did the user press a key? (Windows specific)
        if msvcrt.kbhit():
            # Consume the key press so it doesn't clutter the screen
            msvcrt.getch() 
            print("\n⚡ Manual Trigger Detected!")
            check_new_reports()
            last_scan_time = time.time() # Reset timer so we don't double-scan

        # Sleep briefly to stop the CPU from working too hard
        time.sleep(0.1)

if __name__ == "__main__":
    main()