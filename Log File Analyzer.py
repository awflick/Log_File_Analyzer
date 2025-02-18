# Log File Analyzer

import os
import re
import tkinter as tk
from tkinter import filedialog
import json
import csv

# =====================================
# File Selection & Validation Functions
# =====================================

# Function to prompt user to select a file (JSON, CSV, or TXT)
def select_load_file():
    """ Prompts the user in the CLI to upload a log file, then opens a file selection dialog."""
    # Prompt user for action before opening the file picker
    input("Press Enter to select a log file (JSON, CSV, or TXT)...")

    # Set up tkinter root window (it won’t show up because we don’t call .mainloop())
    root = tk.Tk()
    root.withdraw()  # Hide the main tkinter window

    # File types to allow
    file_types = [("JSON Files", "*.json"),
                  ("CSV Files", "*.csv"),
                  ("Text Files", "*.txt"),
                  ("All Files", "*.*")]

    # Ask user to choose a file
    file_selected = filedialog.askopenfilename(
        title="Select log file to analyze (JSON, CSV, or TXT)",
        filetypes=file_types
    )

    # If no file is selected, return None
    if not file_selected:
        print("No file selected. File will not be loaded.")
        return None

    # Validate the file extension
    if not file_selected.endswith(('.json', '.csv', '.txt')):
        print("Invalid file type. Please select a JSON, CSV, or TXT file.")
        return None

    # Check if the file is empty
    if os.path.getsize(file_selected) == 0:
        print("Error: Selected file is empty.")
        return None

    print(f"File '{file_selected}' successfully loaded.")
    return file_selected

# Load contents of log file based on it's format
def load_file_contents(file_path):
    """Loads the contents of a selected log file based on its format."""
    
    if file_path.endswith('.json'):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)  # Load JSON as dictionary or list
            return data
        except json.JSONDecodeError:
            print("Error: Invalid JSON format.")
            return None

    elif file_path.endswith('.csv'):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                csv_reader = csv.reader(f)
                data = list(csv_reader)  # Convert CSV file into a list of lists
            return data
        except Exception as e:
            print(f"Error loading CSV: {e}")
            return None

    elif file_path.endswith('.txt'):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = f.readlines()  # Read the file into a list of lines
            return data
        except Exception as e:
            print(f"Error loading TXT file: {e}")
            return None

    else:
        print("Unsupported file format.")
        return None


# ===========================
# Default Parameter Functions
# ===========================

# Function for storing and selecting default parameters
def default_parameters():
    parameter_dict = {
        1: "Timestamps",
        2: "IP Addresses",
        3: "Error Levels",
        4: "HTTP Status Codes"
    }

    # Print menu
    for key, value in parameter_dict.items():
        print(f"{key}. {value}")

    # Ask user for input and strip extra spaces
    user_input = input("Enter choices separated by commas (1,2,3,4). Press Enter to skip: ").strip()

    # If user_input is empty, return an empty list right away
    if not user_input:
        print("No choices selected.")
        return []

    # Split by comma and strip each part
    choices = [item.strip() for item in user_input.split(",")]

    # Use a set to avoid duplicates
    selected_set = set()

    for choice_str in choices:
        # Attempt to convert to int
        try:
            choice_int = int(choice_str)
        except ValueError:
            print(f"Invalid number: {choice_str}")
            continue

        # Check if choice is valid
        if choice_int in parameter_dict:
            selected_set.add(parameter_dict[choice_int])  # add to set
        else:
            print(f"No default parameter for choice {choice_int}.")

    # Convert the set to a list
    selected_defaults = list(selected_set)

    # Show what was selected
    if selected_defaults:
        print(f"Selected parameters: {selected_defaults}")
    else:
        print("No valid choices selected.")

    return selected_defaults


# ===========================
# Custom Parameter Functions
# ===========================

# Function to collect and validate custom parameters
def custom_parameters():
    """
    Collects and validates custom parameters (regex or keywords) one by one.
    The user presses Enter on an empty line to finish.
    """
    print("Enter each regex or keyword on a new line. "
          "Press Enter on a blank line to finish.")
    
    custom_params = []
    
    while True:
        # Prompt user for a parameter (or blank to finish)
        param = input("Parameter (leave blank to finish): ").strip()
        
        # If user hits Enter immediately, we're done
        if not param:
            break
        
        # (Optional) Convert to lowercase
        param_lower = param.lower()
        
        # Try to compile as a regex to validate it
        try:
            re.compile(param_lower)
            # If valid, store in custom_params
            custom_params.append(param_lower)
            print(f"Added custom parameter: '{param_lower}'")
        except re.error:
            print(f"Invalid regex: '{param_lower}'. Please try again.")
    
    # Final summary
    print("\nAccepted parameters:", custom_params)
    return custom_params
    
   
# =========================
# Parse and Scan Functions
# =========================

# Function to Parse and Scan Log Files
def parse_scan_data(data, selected_defaults, custom_params):
    """
    Parse and scan log data based on selected default parameters and custom regex patterns.

    :param data: The raw log data (list of lines for TXT/CSV or a list of entries for JSON).
    :param selected_defaults: A list of default parameter names the user selected (e.g., ["Timestamps", "IP Addresses"]).
    :param custom_params: A list of strings that might be user-defined regex patterns.
    :return: A list of dictionaries, each containing details about matched lines/entries.
    """

    import re  # Ensure regex is available

    # Set default regex patterns for commonly searched items
    default_regex = {
        "Timestamps":        r"\b\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}\b",
        "IP Addresses":      r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
        "Error Levels":      r"\b(ERROR|WARNING|INFO|CRITICAL|DEBUG)\b",
        "HTTP Status Codes": r"\b(100|101|200|201|202|204|301|302|304|400|401|403|404|500|501|502|503)\b"
    }

    # 1. Early check: If no parameters were selected at all, exit
    if not selected_defaults and not custom_params:
        print("No parameters selected.")
        return None

    # 2. Build a list of active regex patterns
    active_regex_patterns = []

    # (a) Gather regexes for each default parameter the user selected
    for param in selected_defaults:
        if param in default_regex:
            pattern_str = default_regex[param]
            compiled_pattern = re.compile(pattern_str)
            # Store a tuple of (description, compiled_regex)
            active_regex_patterns.append((param, compiled_pattern))

    # (b) Gather user-defined (custom) regex patterns
    for custom in custom_params:
        try:
            compiled_custom = re.compile(custom)
            # label these simply as "Custom" or store the user string
            active_regex_patterns.append(("Custom", compiled_custom))
        except re.error:
            print(f"Invalid regex: '{custom}'. Skipping this pattern.")

    # 3. Parse the log data: look for matches of active regex patterns
    parsed_log = []  # Store results as a list of dictionaries

    for line_number, entry in enumerate(data, start=1):
        # Convert entry to a string if it's not already
        if isinstance(entry, list):
            line_str = " ".join(entry)
        elif isinstance(entry, dict):
            line_str = str(entry)
        else:
            # Assume it's a string (typical for .txt lines)
            line_str = entry

        # Check each active pattern against this line
        for pattern_name, regex_obj in active_regex_patterns:
            match = regex_obj.search(line_str)
            if match:
                # Create a dictionary capturing details of the match
                result_entry = {
                    "line_number": line_number,
                    "pattern": pattern_name,
                    "matched_text": match.group(0),
                    "full_line": line_str.strip()
                }
                parsed_log.append(result_entry)
                # If you only want one match per line per pattern,
                # this is enough. Otherwise, use findall()/finditer().

    # 4. Return the list of matches (could be empty if nothing matched)
    return parsed_log


# =======================
# Save User Data Functions
# =======================

# Save results to user selected location
def export_results(parsed_log):
    save_path = filedialog.asksaveasfilename(
        defaultextension=".csv",
        filetypes=[("CSV File","*.csv"), ("Text File","*.txt"), ("All Files","*.*")]
    )
    if not save_path:
        print("No file selected for saving.")
        return

    # Based on extension, write CSV or TXT:
    if save_path.endswith(".csv"):
        # Use CSV writer or pandas
        import csv
        with open(save_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["line_number","pattern","matched_text","full_line"])
            writer.writeheader()
            writer.writerows(parsed_log)
    else:
        # Save as plain text
        with open(save_path, "w", encoding="utf-8") as f:
            for entry in parsed_log:
                f.write(f"Line {entry['line_number']}, Pattern: {entry['pattern']}, Matched: {entry['matched_text']}\n")
    print(f"Results saved to {save_path}")


def main_loop():
    """
    Continuously runs the main menu flow until the user decides to exit.
    """
    while True:
        # Call your existing main() function
        main()

        # After main() finishes, ask if the user wants to run again
        run_again = input("\nWould you like to analyze another file? (yes/no): ").strip().lower()
        if run_again != "yes":
            print("Exiting the Log File Analyzer.")
            break

# ====================
# Main Program and CLI
# ====================

def main():
    """
    Main CLI flow for the Log File Analyzer.
    """
    # 1. Select the file
    file_path = select_load_file()
    if not file_path:
        # The user cancelled or didn't select a file
        return

    # 2. Load the file data
    data = load_file_contents(file_path)
    if data is None:
        # Loading failed (invalid format or empty file)
        return

    # 3. Get default parameters
    selected_defaults = default_parameters()

    # 4. Ask the user if they want to add custom parameters
    wants_custom = input("Would you like to enter custom search terms? (yes/no): ").strip().lower()
    if wants_custom == "yes":
        custom_params = custom_parameters()
    else:
        custom_params = []

    # 5. Summarize all final parameters before parsing
    print("\nFinal parameters:")
    if selected_defaults:
        print("  Default:", selected_defaults)
    if custom_params:
        print("  Custom:", custom_params)
    print()

    # 6. Parse & scan the data
    parsed_log = parse_scan_data(data, selected_defaults, custom_params)
    if parsed_log is None:
        # The parser returns None if no parameters were selected or something else went wrong
        return

    # 7. Do a basic analysis / summary on the results
    if not parsed_log:
        print("No matches found with the selected parameters.")
    else:
        # Count how many times each pattern matched
        match_counts = {}
        for entry in parsed_log:
            pattern = entry["pattern"]
            match_counts[pattern] = match_counts.get(pattern, 0) + 1

        print("\nMatch Summary:")
        for pattern, count in match_counts.items():
            print(f"  {pattern}: {count} matches")

        # (Optional) Show the first few matches
        print("\nSample of matched entries (up to first 5):")
        for match in parsed_log[:5]:
            print(f"  Line {match['line_number']}, Pattern: {match['pattern']}, Match: {match['matched_text']}")

        # 8. Ask if user wants to export results
        export_decision = input("\nWould you like to export the results? (yes/no): ").strip().lower()
        if export_decision == "yes":
            export_results(parsed_log)  # Make sure you’ve defined `export_results()`
        else:
            print("Results not exported.")

if __name__ == "__main__":
    main_loop()


