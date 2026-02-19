"""
================================================================================
PASSWORD STRENGTH CHECKER
Version: 2.0
================================================================================
This tool evaluates password strength based on multiple security criteria
and provides actionable feedback for improvement.
================================================================================
"""

import re
import string
import math
from datetime import datetime
from typing import Dict, List, Tuple

# ============================================================================
# SECTION 1: PASSWORD CHECKING FUNCTIONS
# ============================================================================

def check_length(password: str) -> Tuple[int, int, str]:
    """
    Check password length and award points.
    
    SCORING:
    - 0-7 chars: 0 points
    - 8-11 chars: 10 points
    - 12-15 chars: 20 points
    - 16-19 chars: 30 points
    - 20+ chars: 40 points
    
    Returns: (points, max_points, feedback)
    """
    length = len(password)
    
    if length == 0:
        return 0, 40, "❌ No password entered"
    elif length < 8:
        return 0, 40, f"❌ Too short ({length} chars). Minimum 8 characters required."
    elif length < 12:
        return 10, 40, f"⚠️  Minimum length ({length} chars). Consider 12+ characters."
    elif length < 16:
        return 20, 40, f"✓ Good length ({length} chars)"
    elif length < 20:
        return 30, 40, f"✓ Very good length ({length} chars)"
    else:
        return 40, 40, f"✅ Excellent length ({length} chars)"


def check_character_types(password: str) -> Tuple[int, int, List[str]]:
    """
    Check for presence of different character types.
    
    Points per character type: 15 points each (60 total)
    Types: Uppercase, Lowercase, Numbers, Special characters
    
    Returns: (points, max_points, feedback_list)
    """
    points = 0
    max_points = 60
    feedback = []
    
    # Check for uppercase letters
    if re.search(r'[A-Z]', password):
        points += 15
        feedback.append("✅ Contains uppercase letters")
    else:
        feedback.append("❌ Add uppercase letters (A-Z)")
    
    # Check for lowercase letters
    if re.search(r'[a-z]', password):
        points += 15
        feedback.append("✅ Contains lowercase letters")
    else:
        feedback.append("❌ Add lowercase letters (a-z)")
    
    # Check for numbers
    if re.search(r'[0-9]', password):
        points += 15
        feedback.append("✅ Contains numbers")
    else:
        feedback.append("❌ Add numbers (0-9)")
    
    # Check for special characters
    special_chars = r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]'
    if re.search(special_chars, password):
        points += 15
        feedback.append("✅ Contains special characters")
    else:
        feedback.append("❌ Add special characters (!@#$% etc.)")
    
    return points, max_points, feedback


def check_common_patterns(password: str) -> Tuple[int, int, List[str]]:
    """
    Check for common weak patterns.
    
    Deducts points for bad patterns:
    - Common sequences: -5 each
    - Common passwords: -10
    - Personal info patterns: -5
    
    Returns: (points_deducted, max_penalty, feedback)
    """
    points_lost = 0
    max_penalty = 30
    feedback = []
    
    # Common sequences to check (reverse included too)
    sequences = [
        '123', '234', '345', '456', '567', '678', '789', '890',
        'abc', 'bcd', 'cde', 'def', 'efg', 'fgh', 'ghi', 'hij',
        'ijk', 'jkl', 'klm', 'lmn', 'mno', 'nop', 'opq', 'pqr',
        'qrs', 'rst', 'stu', 'tuv', 'uvw', 'vwx', 'wxy', 'xyz',
        'qwerty', 'asdfgh', 'zxcvbn', 'password'
    ]
    
    # Check for sequences
    password_lower = password.lower()
    for seq in sequences:
        if seq in password_lower or seq[::-1] in password_lower:
            points_lost += 5
            feedback.append(f"⚠️  Contains common sequence: '{seq}'")
            break  # Only penalize once
    
    # Check for common passwords
    common_passwords = [
        'password', '123456', 'qwerty', 'admin', 'welcome',
        'monkey', 'dragon', 'letmein', 'password1', 'abc123'
    ]
    
    if password_lower in common_passwords:
        points_lost += 10
        feedback.append(f"❌ Very common password: '{password}'")
    
    # Check for repeated characters
    if re.search(r'(.)\1{2,}', password):
        points_lost += 5
        feedback.append("⚠️  Contains repeated characters (aaa, 111, etc.)")
    
    # Check for personal info patterns (simple check)
    personal_patterns = [
        r'\d{4}$',  # Year at end (1990, 2023)
        r'^\d{4}',  # Year at start
        r'\d{6}$',  # Date pattern (010190)
    ]
    
    for pattern in personal_patterns:
        if re.search(pattern, password):
            points_lost += 5
            feedback.append("⚠️  Might contain personal info (birth year/date)")
            break
    
    return points_lost, max_penalty, feedback


def check_entropy(password: str) -> Tuple[int, int, str]:
    """
    Calculate password entropy (measure of randomness).
    
    Entropy = log2(charset_size ^ length)
    Higher entropy = more secure
    
    Returns: (points, max_points, feedback)
    """
    length = len(password)
    
    # Determine charset size
    charset = 0
    
    if re.search(r'[a-z]', password):
        charset += 26  # lowercase
    if re.search(r'[A-Z]', password):
        charset += 26  # uppercase
    if re.search(r'[0-9]', password):
        charset += 10  # digits
    if re.search(r'[^a-zA-Z0-9]', password):
        # Special characters (approximately 32 common ones)
        charset += 32
    
    # If charset is 0 (empty password)
    if charset == 0:
        return 0, 20, "❌ No characters detected"
    
    # Calculate entropy
    entropy = math.log2(charset ** length)
    
    # Convert entropy to points (0-20 scale)
    if entropy < 28:  # Very weak
        points = 0
        feedback = f"❌ Very low entropy ({entropy:.1f} bits)"
    elif entropy < 36:  # Weak
        points = 5
        feedback = f"⚠️  Low entropy ({entropy:.1f} bits)"
    elif entropy < 45:  # Medium
        points = 10
        feedback = f"✓ Moderate entropy ({entropy:.1f} bits)"
    elif entropy < 55:  # Strong
        points = 15
        feedback = f"✓ Good entropy ({entropy:.1f} bits)"
    else:  # Very strong
        points = 20
        feedback = f"✅ Excellent entropy ({entropy:.1f} bits)"
    
    return points, 20, feedback


def check_uniqueness(password: str, previous_passwords: List[str] = None) -> Tuple[int, int, str]:
    """
    Check if password is similar to previous passwords.
    
    Returns: (points, max_points, feedback)
    """
    if previous_passwords is None:
        previous_passwords = []
    
    # Simple similarity check (you can expand this)
    password_lower = password.lower()
    
    for prev_pass in previous_passwords:
        prev_lower = prev_pass.lower()
        
        # Check for exact match
        if password_lower == prev_lower:
            return 0, 10, "❌ Password reused from previous check"
        
        # Check for high similarity (80%+ same)
        if len(password_lower) > 5 and len(prev_lower) > 5:
            # Simple similarity check
            common_chars = sum(1 for c in password_lower if c in prev_lower)
            similarity = common_chars / max(len(password_lower), len(prev_lower))
            
            if similarity > 0.7:
                return 5, 10, "⚠️  Similar to previous password"
    
    return 10, 10, "✅ Unique password"


# ============================================================================
# SECTION 2: MAIN ASSESSMENT FUNCTION
# ============================================================================

def assess_password_strength(password: str, previous_passwords: List[str] = None) -> Dict:
    """
    Main function to assess password strength.
    
    Returns a dictionary with:
    - total_score: 0-100
    - strength_level: Very Weak/Weak/Medium/Strong/Very Strong
    - detailed_feedback: List of improvement suggestions
    - breakdown: Score breakdown by category
    - time_to_crack: Estimated cracking time
    """
    
    if previous_passwords is None:
        previous_passwords = []
    
    # Initialize results
    results = {
        'password': password,
        'length': len(password),
        'total_score': 0,
        'max_score': 150,  # Sum of all max points
        'strength_level': '',
        'detailed_feedback': [],
        'breakdown': {},
        'time_to_crack': '',
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    # 1. Check length
    length_points, length_max, length_feedback = check_length(password)
    results['breakdown']['length'] = {
        'points': length_points,
        'max': length_max,
        'feedback': length_feedback
    }
    results['total_score'] += length_points
    
    # 2. Check character types
    char_points, char_max, char_feedback = check_character_types(password)
    results['breakdown']['character_types'] = {
        'points': char_points,
        'max': char_max,
        'feedback': char_feedback
    }
    results['total_score'] += char_points
    
    # 3. Check for common patterns (deduct points)
    pattern_penalty, pattern_max, pattern_feedback = check_common_patterns(password)
    results['breakdown']['pattern_check'] = {
        'points_lost': pattern_penalty,
        'max_penalty': pattern_max,
        'feedback': pattern_feedback
    }
    results['total_score'] -= pattern_penalty
    
    # 4. Check entropy
    entropy_points, entropy_max, entropy_feedback = check_entropy(password)
    results['breakdown']['entropy'] = {
        'points': entropy_points,
        'max': entropy_max,
        'feedback': entropy_feedback
    }
    results['total_score'] += entropy_points
    
    # 5. Check uniqueness
    unique_points, unique_max, unique_feedback = check_uniqueness(password, previous_passwords)
    results['breakdown']['uniqueness'] = {
        'points': unique_points,
        'max': unique_max,
        'feedback': unique_feedback
    }
    results['total_score'] += unique_points
    
    # Ensure score doesn't go negative
    results['total_score'] = max(0, results['total_score'])
    
    # Calculate percentage score (0-100)
    percentage_score = (results['total_score'] / 150) * 100
    
    # Determine strength level
    if percentage_score < 30:
        strength = "Very Weak"
        color = "🔴"
    elif percentage_score < 50:
        strength = "Weak"
        color = "🟠"
    elif percentage_score < 70:
        strength = "Medium"
        color = "🟡"
    elif percentage_score < 85:
        strength = "Strong"
        color = "🟢"
    else:
        strength = "Very Strong"
        color = "💪"
    
    results['strength_level'] = f"{color} {strength}"
    results['percentage_score'] = round(percentage_score, 1)
    
    # Compile all feedback
    all_feedback = []
    
    # Add length feedback
    if isinstance(length_feedback, str):
        all_feedback.append(length_feedback)
    
    # Add character type feedback
    all_feedback.extend(char_feedback)
    
    # Add pattern feedback
    all_feedback.extend(pattern_feedback)
    
    # Add entropy feedback
    all_feedback.append(entropy_feedback)
    
    # Add uniqueness feedback
    all_feedback.append(unique_feedback)
    
    results['detailed_feedback'] = all_feedback
    
    # Estimate time to crack
    results['time_to_crack'] = estimate_crack_time(password, percentage_score)
    
    return results


def estimate_crack_time(password: str, strength_score: float) -> str:
    """
    Estimate time to crack password (simplified).
    
    Note: This is a simplified estimation for educational purposes.
    Real cracking time depends on many factors including hardware,
    algorithm, and attacker resources.
    """
    length = len(password)
    
    # Very rough estimation based on length and complexity
    charset_size = 0
    if re.search(r'[a-z]', password):
        charset_size += 26
    if re.search(r'[A-Z]', password):
        charset_size += 26
    if re.search(r'[0-9]', password):
        charset_size += 10
    if re.search(r'[^a-zA-Z0-9]', password):
        charset_size += 32
    
    # If no charset detected (empty or weird characters)
    if charset_size == 0:
        charset_size = 1
    
    # Total possible combinations
    total_combinations = charset_size ** length
    
    # Assume 10 billion guesses per second (modern GPU)
    guesses_per_second = 10_000_000_000
    
    seconds_to_crack = total_combinations / guesses_per_second
    
    # Convert to human readable time
    if seconds_to_crack < 1:
        return "Instantly"
    elif seconds_to_crack < 60:
        return f"{seconds_to_crack:.0f} seconds"
    elif seconds_to_crack < 3600:
        minutes = seconds_to_crack / 60
        return f"{minutes:.0f} minutes"
    elif seconds_to_crack < 86400:
        hours = seconds_to_crack / 3600
        return f"{hours:.0f} hours"
    elif seconds_to_crack < 31536000:  # Less than 1 year
        days = seconds_to_crack / 86400
        return f"{days:.0f} days"
    elif seconds_to_crack < 3153600000:  # Less than 100 years
        years = seconds_to_crack / 31536000
        return f"{years:.1f} years"
    else:
        return "Centuries"


# ============================================================================
# SECTION 3: VISUAL DISPLAY FUNCTIONS
# ============================================================================

def display_strength_meter(score: float) -> str:
    """
    Create a visual strength meter.
    
    Returns: ASCII progress bar
    """
    filled_length = int(round(score / 100 * 40))
    bar = '█' * filled_length + '░' * (40 - filled_length)
    
    # Color code based on score
    if score < 30:
        color_code = "31"  # Red
    elif score < 50:
        color_code = "33"  # Yellow
    elif score < 70:
        color_code = "93"  # Light yellow
    elif score < 85:
        color_code = "32"  # Green
    else:
        color_code = "92"  # Light green
    
    return f"\033[{color_code}m[{bar}]\033[0m {score:.1f}%"


def display_results(results: Dict):
    """
    Display assessment results in a user-friendly format.
    """
    password = results['password']
    strength = results['strength_level']
    score = results['percentage_score']
    
    print("\n" + "="*70)
    print("                    PASSWORD STRENGTH REPORT")
    print("="*70)
    
    # Display password (masked for security)
    masked_password = password[0] + "*" * (len(password) - 2) + password[-1] if len(password) > 2 else "***"
    print(f"\n🔐 Password: {masked_password}")
    print(f"📏 Length: {results['length']} characters")
    
    # Display strength meter
    print(f"\n📊 Strength: {strength}")
    print(f"   {display_strength_meter(score)}")
    
    # Display score breakdown
    print("\n" + "-"*70)
    print("📈 SCORE BREAKDOWN")
    print("-"*70)
    
    breakdown = results['breakdown']
    
    print(f"\n1. Length Check: {breakdown['length']['points']}/{breakdown['length']['max']} points")
    print(f"   ➤ {breakdown['length']['feedback']}")
    
    print(f"\n2. Character Types: {breakdown['character_types']['points']}/{breakdown['character_types']['max']} points")
    for fb in breakdown['character_types']['feedback'][:2]:  # Show first 2
        print(f"   ➤ {fb}")
    if len(breakdown['character_types']['feedback']) > 2:
        print(f"   ... and {len(breakdown['character_types']['feedback'])-2} more")
    
    if breakdown['pattern_check']['points_lost'] > 0:
        print(f"\n3. Pattern Check: -{breakdown['pattern_check']['points_lost']} points")
        for fb in breakdown['pattern_check']['feedback']:
            print(f"   ➤ {fb}")
    
    print(f"\n4. Entropy (Randomness): {breakdown['entropy']['points']}/{breakdown['entropy']['max']} points")
    print(f"   ➤ {breakdown['entropy']['feedback']}")
    
    print(f"\n5. Uniqueness: {breakdown['uniqueness']['points']}/{breakdown['uniqueness']['max']} points")
    print(f"   ➤ {breakdown['uniqueness']['feedback']}")
    
    # Display crack time estimation
    print("\n" + "-"*70)
    print("⏱️  SECURITY ESTIMATE")
    print("-"*70)
    print(f"\nEstimated time to crack: {results['time_to_crack']}")
    print("(Based on 10 billion guesses/second with modern hardware)")
    
    # Display improvement suggestions
    print("\n" + "-"*70)
    print("💡 IMPROVEMENT SUGGESTIONS")
    print("-"*70)
    
    # Collect suggestions from low-scoring areas
    suggestions = []
    
    if breakdown['length']['points'] < 20:
        suggestions.append("• Increase length to at least 16 characters")
    
    if breakdown['character_types']['points'] < 45:
        suggestions.append("• Include ALL character types: uppercase, lowercase, numbers, and special characters")
    
    if breakdown['pattern_check']['points_lost'] > 0:
        suggestions.append("• Avoid common words, sequences, or patterns")
    
    if breakdown['entropy']['points'] < 10:
        suggestions.append("• Make password more random (avoid dictionary words)")
    
    if not suggestions:  # If password is already strong
        suggestions.append("✅ Your password meets all basic security criteria!")
        suggestions.append("• Consider using a password manager")
        suggestions.append("• Enable two-factor authentication where available")
    
    for i, suggestion in enumerate(suggestions, 1):
        print(f"{i}. {suggestion}")
    
    print("\n" + "="*70)


# ============================================================================
# SECTION 4: PASSWORD GENERATOR (BONUS FEATURE)
# ============================================================================

def generate_strong_password(length: int = 16) -> str:
    """
    Generate a strong random password.
    
    Parameters:
        length (int): Desired password length (default: 16)
    
    Returns:
        str: Generated password
    """
    import secrets
    
    if length < 8:
        length = 8
        print("⚠️  Minimum length is 8 characters. Setting to 8.")
    
    # Define character sets
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    # Ensure at least one of each type
    all_chars = lowercase + uppercase + digits + special_chars
    
    # Generate password
    while True:
        password = [
            secrets.choice(lowercase),
            secrets.choice(uppercase),
            secrets.choice(digits),
            secrets.choice(special_chars)
        ]
        
        # Fill the rest with random characters
        for _ in range(length - 4):
            password.append(secrets.choice(all_chars))
        
        # Shuffle the password
        secrets.SystemRandom().shuffle(password)
        password = ''.join(password)
        
        # Check if it meets criteria
        if (len(password) >= length and
            re.search(r'[a-z]', password) and
            re.search(r'[A-Z]', password) and
            re.search(r'[0-9]', password) and
            re.search(r'[^a-zA-Z0-9]', password)):
            return password


# ============================================================================
# SECTION 5: MAIN MENU AND USER INTERFACE
# ============================================================================

def display_banner():
    """Display program banner."""
    banner = """
    ╔══════════════════════════════════════════════════════════╗
    ║              PASSWORD STRENGTH CHECKER                   ║
    ║                    Version 2.0                           ║
    ╟──────────────────────────────────────────────────────────╢
    ║  Features:                                               ║
    ║  • Comprehensive password analysis                       ║
    ║  • Strength scoring (0-100%)                             ║
    ║  • Detailed improvement suggestions                      ║
    ║  • Password generator                                    ║
    ║  • Security time estimation                              ║
    ╚══════════════════════════════════════════════════════════╝
    """
    print(banner)

def display_menu():
    """Display main menu."""
    menu = """
    ┌──────────────────────────────────────────────────────────┐
    │                         MAIN MENU                        │
    ├──────────────────────────────────────────────────────────┤
    │  1. 🔐  Check Password Strength                          │
    │  2. 🎲  Generate Strong Password                         │
    │  3. 📊  View Password Guidelines                         │
    │  4. 🧪  Test Example Passwords                           │
    │  5. 🚪  Exit Program                                     │
    └──────────────────────────────────────────────────────────┘
    """
    print(menu)

def view_guidelines():
    """Display password security guidelines."""
    guidelines = """
    📚 PASSWORD SECURITY GUIDELINES
    ================================
    
    🎯 RECOMMENDED:
    • Length: 12+ characters (16+ for important accounts)
    • Mix: Uppercase + Lowercase + Numbers + Special characters
    • Randomness: Avoid dictionary words, use random sequences
    • Uniqueness: Different password for each account
    • Management: Use a password manager
    
    🚫 AVOID:
    • Common words: "password", "admin", "welcome"
    • Sequences: "123456", "qwerty", "abcdef"
    • Personal info: Name, birthdate, pet's name
    • Short passwords: Less than 8 characters
    • Password reuse across sites
    
    💡 TIPS:
    1. Use passphrases: "CorrectHorseBatteryStaple42!"
    2. Consider acronyms: "IW!2gtTH@2024" (I want to go to TH in 2024)
    3. Add randomness: "Blue$42Tiger*9Coffee@15"
    4. Regular updates: Change passwords every 90 days
    5. Two-factor: Always enable 2FA when available
    
    🔐 STRONG PASSWORD EXAMPLES:
    • L0ng$ecureP@ssw0rd!2024
    • C0mpl3x#P@ss!Phr@se
    • $tr0ngP@$$w0rdW1thNumb3rs
    """
    print(guidelines)

def test_examples():
    """Test example passwords to demonstrate tool."""
    examples = [
        "password",          # Very weak
        "12345678",          # Weak
        "Password123",       # Medium
        "P@ssw0rd!2024",     # Strong
        "L0ng$ecureP@ssw0rd!2024#Complex",  # Very strong
    ]
    
    print("\n🧪 TESTING EXAMPLE PASSWORDS")
    print("="*60)
    
    for example in examples:
        print(f"\nTesting: {example}")
        results = assess_password_strength(example)
        print(f"Strength: {results['strength_level']}")
        print(f"Score: {results['percentage_score']:.1f}%")
        print(f"Crack time: {results['time_to_crack']}")
        print("-"*40)

def main():
    """Main program function."""
    display_banner()
    
    # Store previously checked passwords (for uniqueness check)
    previous_passwords = []
    
    while True:
        display_menu()
        
        try:
            choice = input("\nEnter your choice (1-5): ").strip()
            
            if choice == "1":
                print("\n" + "="*60)
                print("              PASSWORD STRENGTH CHECK")
                print("="*60)
                
                # Get password (with option to hide input)
                password = input("\nEnter password to check: ")
                
                if not password:
                    print("❌ No password entered. Try again.")
                    continue
                
                # Assess password
                print("\n🔍 Analyzing password...")
                results = assess_password_strength(password, previous_passwords)
                
                # Store for uniqueness check
                previous_passwords.append(password)
                
                # Display results
                display_results(results)
                
                # Offer to save report
                save_report = input("\nSave report to file? (yes/no): ").lower()
                if save_report in ['yes', 'y']:
                    save_results_to_file(results)
                    
            elif choice == "2":
                print("\n" + "="*60)
                print("              PASSWORD GENERATOR")
                print("="*60)
                
                try:
                    length = int(input("\nEnter desired password length (8-32): ") or "16")
                    if length < 8:
                        length = 8
                    elif length > 32:
                        length = 32
                        
                    password = generate_strong_password(length)
                    
                    print(f"\n✅ Generated Password: {password}")
                    print(f"   Length: {len(password)} characters")
                    
                    # Also check its strength
                    results = assess_password_strength(password, previous_passwords)
                    print(f"\n📊 Strength: {results['strength_level']}")
                    print(f"   Score: {results['percentage_score']:.1f}%")
                    
                    # Offer to use this password
                    use_it = input("\nUse this password? (yes/no): ").lower()
                    if use_it in ['yes', 'y']:
                        previous_passwords.append(password)
                        
                except ValueError:
                    print("❌ Please enter a valid number")
                    
            elif choice == "3":
                view_guidelines()
                
            elif choice == "4":
                test_examples()
                
            elif choice == "5":
                print("\n" + "="*60)
                print("Thank you for using Password Strength Checker!")
                print("Stay secure! 🔐")
                print("="*60)
                break
                
            else:
                print("❌ Invalid choice! Please enter 1-5.")
            
            # Pause before next operation
            if choice != "5":
                input("\nPress Enter to continue...")
                
        except KeyboardInterrupt:
            print("\n\n⚠️  Program interrupted. Exiting...")
            break
        except Exception as e:
            print(f"\n❌ An error occurred: {e}")
            input("\nPress Enter to continue...")

def save_results_to_file(results: Dict):
    """Save assessment results to a text file."""
    filename = f"password_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    
    try:
        with open(filename, 'w') as f:
            f.write("="*60 + "\n")
            f.write("PASSWORD STRENGTH REPORT\n")
            f.write("="*60 + "\n\n")
            
            f.write(f"Date: {results['timestamp']}\n")
            f.write(f"Password Length: {results['length']} characters\n")
            f.write(f"Strength Level: {results['strength_level']}\n")
            f.write(f"Score: {results['percentage_score']:.1f}%\n\n")
            
            f.write("-"*60 + "\n")
            f.write("DETAILED FEEDBACK\n")
            f.write("-"*60 + "\n\n")
            
            for feedback in results['detailed_feedback']:
                f.write(f"• {feedback}\n")
            
            f.write(f"\nEstimated crack time: {results['time_to_crack']}\n")
            
            f.write("\n" + "="*60 + "\n")
            f.write("END OF REPORT\n")
            f.write("="*60 + "\n")
        
        print(f"✅ Report saved to: {filename}")
        
    except Exception as e:
        print(f"❌ Could not save report: {e}")

# ============================================================================
# SECTION 6: PROGRAM ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Goodbye!")
    except Exception as e:
        print(f"\n❌ Critical error: {e}")
        print("Please check your Python installation.")
