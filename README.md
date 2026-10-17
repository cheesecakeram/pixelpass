# pixelpass
![image alt](https://github.com/cheesecakeram/pixelpass/blob/65e4453009cddcd0a9ed65440cb0674d3ee9e84d/screenshot1.png)

use pixelpass at your own risk!

Features:
  Generate passwords with customizable length, character types, excluded characters, and excluded words or sequences.
  Generate passphrases with a chosen word count and separator.
  Generate usernames.
  Create, view, edit, and delete saved entries.
  Run offline.
 
Dependencies:
  python3
  openpyxl

Files:
  pixelpass - main folder, pixelpass.py - the script, vault.xlsx - your vault, settings.txt - stores vault file name. Script generates needed files itself.
  
Use:
  Run pixelpass.py with Python and choose an action from the numbered menu. pixelpass asks for confirmation before saving, revealing, editing, or deleting entries.

Offline use:
  pixelpass does not need an internet connection to run once its dependency is available. Staying offline can reduce exposure to network-based threats, which is a security benefit. It does not encrypt the vault or protect it from someone who can access the files, so keep the pixelpass folder somewhere secure.




Script: 
from pathlib import Path
import secrets
import shutil
import sys

try:
    from openpyxl import Workbook, load_workbook
except ImportError:
    print("pixelpass requires openpyxl.")
    raise SystemExit(1)


SCRIPT_PATH = Path(__file__).resolve()
if SCRIPT_PATH.parent.name == "pixelpass":
    DATA_DIR = SCRIPT_PATH.parent
else:
    DATA_DIR = Path.cwd() / "pixelpass"
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    destination = DATA_DIR / "pixelpass.py"
    if SCRIPT_PATH != destination:
        try:
            shutil.copy2(SCRIPT_PATH, destination)
        except OSError:
            pass

DATA_DIR.mkdir(parents=True, exist_ok=True)
SETTINGS_PATH = DATA_DIR / "settings.txt"
HEADERS = ["Site or custom name", "Username", "Email", "Password"]
DEFAULT_SETTINGS = {"vault_file": "vault.xlsx"}


def load_settings():
    settings = DEFAULT_SETTINGS.copy()
    if SETTINGS_PATH.exists():
        try:
            for line in SETTINGS_PATH.read_text(encoding="utf-8").splitlines():
                if "=" in line:
                    key, value = line.split("=", 1)
                    settings[key.strip()] = value.strip()
        except OSError:
            pass
    vault_name = Path(settings.get("vault_file", "vault.xlsx")).name
    if not vault_name.lower().endswith(".xlsx"):
        vault_name = "vault.xlsx"
    settings["vault_file"] = vault_name
    save_settings(settings)
    return settings


def save_settings(settings):
    lines = [f"{key}={value}" for key, value in sorted(settings.items())]
    SETTINGS_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")


SETTINGS = load_settings()
VAULT_PATH = DATA_DIR / SETTINGS["vault_file"]


def create_vault():
    workbook = Workbook()
    sheet = workbook.active
    sheet.title = "Vault"
    sheet.append(HEADERS)
    sheet.freeze_panes = "A2"
    sheet.column_dimensions["A"].width = 28
    sheet.column_dimensions["B"].width = 28
    sheet.column_dimensions["C"].width = 32
    sheet.column_dimensions["D"].width = 36
    workbook.save(VAULT_PATH)


def ensure_vault():
    if not VAULT_PATH.exists():
        create_vault()


def load_entries():
    ensure_vault()
    workbook = load_workbook(VAULT_PATH)
    sheet = workbook.active
    if sheet.max_row == 1 and all(sheet.cell(1, i + 1).value is None for i in range(4)):
        for column, header in enumerate(HEADERS, start=1):
            sheet.cell(1, column, header)
        workbook.save(VAULT_PATH)
    actual_headers = [sheet.cell(1, i + 1).value for i in range(4)]
    if actual_headers != HEADERS:
        raise ValueError("The vault spreadsheet has unexpected columns.")
    entries = []
    for row in range(2, sheet.max_row + 1):
        values = [sheet.cell(row, col).value for col in range(1, 5)]
        if any(value is not None for value in values):
            entries.append((row, ["" if value is None else str(value) for value in values]))
    workbook.close()
    return entries


def write_cell(cell, value):
    cell.value = str(value)
    cell.data_type = "s"
    cell.number_format = "@"


def save_entry(row, values):
    workbook = load_workbook(VAULT_PATH)
    sheet = workbook.active
    for column, value in enumerate(values, start=1):
        write_cell(sheet.cell(row, column), value)
    workbook.save(VAULT_PATH)
    workbook.close()


def append_entry(values):
    workbook = load_workbook(VAULT_PATH)
    sheet = workbook.active
    row = max(2, sheet.max_row + 1)
    for column, value in enumerate(values, start=1):
        write_cell(sheet.cell(row, column), value)
    workbook.save(VAULT_PATH)
    workbook.close()


def delete_entry(row):
    workbook = load_workbook(VAULT_PATH)
    workbook.active.delete_rows(row, 1)
    workbook.save(VAULT_PATH)
    workbook.close()


def ask_yes_no(prompt, default=None):
    while True:
        suffix = " [y/n]: " if default is None else (" [Y/n]: " if default else " [y/N]: ")
        answer = input(prompt + suffix).strip().lower()
        if not answer and default is not None:
            return default
        if answer in ("y", "yes"):
            return True
        if answer in ("n", "no"):
            return False
        print("Enter y or n.")


def confirm(prompt):
    return ask_yes_no(prompt + " This action may be difficult to undo.", False)


def read_int(prompt, minimum, maximum):
    while True:
        raw = input(prompt).strip()
        try:
            value = int(raw)
        except ValueError:
            print("Enter a whole number.")
            continue
        if minimum <= value <= maximum:
            return value
        print(f"Enter a number from {minimum} to {maximum}.")


def read_choice(prompt, choices):
    choices = {str(choice).lower() for choice in choices}
    while True:
        answer = input(prompt).strip().lower()
        if answer in choices:
            return answer
        print("Choose one of: " + ", ".join(sorted(choices)))


def show_warning():
    print("=" * 68)
    print("pixelpass stores passwords as readable text in an unencrypted")
    print("spreadsheet. Anyone who can access the folder or a copy of the")
    print("spreadsheet can read your saved data. Keep the folder protected.")
    print("=" * 68)


def generate_password():
    print("\nGenerate password")
    length = read_int("Password length (1-4096): ", 1, 4096)

    categories = []
    if ask_yes_no("Allow lowercase letters (a-z)?", True):
        categories.append(("lowercase", "abcdefghijklmnopqrstuvwxyz"))
    if ask_yes_no("Allow uppercase letters (A-Z)?", True):
        categories.append(("uppercase", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
    if ask_yes_no("Allow digits (0-9)?", True):
        categories.append(("digits", "0123456789"))
    if ask_yes_no("Allow symbols?", True):
        categories.append(("symbols", "!@#$%^&*()-_=+[]{};:,.<>?/\\|~`'\""))

    extra = input("Extra characters to allow (Enter for none): ")
    if extra:
        categories.append(("custom characters", extra))

    if not categories:
        print("Select at least one character category.")
        return

    excluded_chars = input("Characters to exclude (Enter for none): ")
    excluded_terms = input(
        "Words or character sequences to exclude, comma-separated (Enter for none): "
    )
    forbidden = [term.strip().casefold() for term in excluded_terms.split(",") if term.strip()]

    cleaned_categories = []
    for name, characters in categories:
        cleaned = "".join(dict.fromkeys(char for char in characters if char not in excluded_chars))
        if cleaned:
            cleaned_categories.append((name, cleaned))
        else:
            print(f"The {name} category has no allowed characters left.")

    if not cleaned_categories:
        print("No allowed characters remain.")
        return

    if length < len(cleaned_categories):
        print(
            f"Length must be at least {len(cleaned_categories)} to include "
            "at least one character from every selected category."
        )
        return

    pool = "".join(dict.fromkeys("".join(chars for _, chars in cleaned_categories)))
    rng = secrets.SystemRandom()

    for _ in range(10000):
        result = [secrets.choice(chars) for _, chars in cleaned_categories]
        result.extend(secrets.choice(pool) for _ in range(length - len(result)))
        rng.shuffle(result)
        password = "".join(result)
        if not any(term in password.casefold() for term in forbidden):
            print("\nGenerated password:")
            print(password)
            return

    print("Could not satisfy those exclusions. Try fewer excluded words or sequences.")


WORDS = (
    "amber anchor apple arch artist autumn badger bamboo beacon berry birch bird"
    " blossom blue breeze brook cabin cactus candle canyon cedar cherry circle"
    " cloud coast cocoa comet coral cosmos cotton cove crystal daisy dawn delta"
    " diamond drift dune eagle earth echo elm ember fabric falcon fern field"
    " firefly fjord flame forest fox frost garden garlic gazelle glacier globe"
    " gold granite grape grass harbor hazel heart honey horizon island ivory"
    " jasmine jigsaw jungle juniper kestrel kitchen lagoon lantern lemon lilac"
    " lily lizard lotus maple marble meadow melody meteor mint mirror mist"
    " moon morning mountain music navy nectar nickel night noodle north ocean"
    " olive orbit orchid otter oyster palace paper pebble pepper petal piano"
    " pickle pillow planet plum pocket poetry pond poppy prairie puzzle quartz"
    " rabbit rainbow raven recipe reef river robin rocket rose ruby saddle saffron"
    " sailor scarlet season shadow shell silver sky smoke snow solar sparrow"
    " spice spring spruce star stone storm summer sunset swift temple thimble"
    " thunder tiger timber toast tomato topaz torch tulip tunnel turtle valley"
    " velvet violet walnut water wheat willow window winter wren yellow zephyr"
).split()


def generate_passphrase():
    print("\nGenerate passphrase")
    count = read_int("Number of words (2-50): ", 2, 50)
    separator = input("Separator between words (Enter for a space): ")
    if separator == "":
        separator = " "
    words = [secrets.choice(WORDS) for _ in range(count)]
    if ask_yes_no("Capitalize the first letter of each word?", False):
        words = [word.capitalize() for word in words]
    print("\nGenerated passphrase:")
    print(separator.join(words))


def generate_username():
    print("\nGenerate username")
    base = input("Optional name or word to include (Enter for random): ").strip()
    separator = input("Separator to use (Enter for underscore): ")
    if separator == "":
        separator = "_"
    style = read_choice(
        "Choose style: 1=random word + digits, 2=two random words, 3=your word + random digits: ",
        ("1", "2", "3"),
    )
    if style == "1":
        word = secrets.choice(WORDS)
        digits = "".join(secrets.choice("0123456789") for _ in range(4))
        username = separator.join((word, digits))
    elif style == "2":
        username = separator.join((secrets.choice(WORDS), secrets.choice(WORDS)))
    else:
        if not base:
            base = input("Enter a name or word: ").strip()
        if not base:
            print("A name or word is required for this style.")
            return
        digits = "".join(secrets.choice("0123456789") for _ in range(4))
        username = separator.join((base, digits))
    print("\nGenerated username:")
    print(username)


def create_new_entry():
    print("\nCreate new password")
    site = input("Site or custom name: ").strip()
    if not site:
        print("A site or custom name is required.")
        return

    try:
        entries = load_entries()
    except Exception as error:
        print(f"Could not read the vault: {error}")
        return

    if any(values[0].casefold() == site.casefold() for _, values in entries):
        print("That site or custom name already exists. Edit its saved entry instead.")
        return

    username = ""
    password = ""
    if ask_yes_no("Do you want to create a username?"):
        if ask_yes_no("Generate a username now?", True):
            generate_username()
            username = input("Username to save (paste or type it here): ")
        else:
            username = input("Username: ")

    email = input("Email (Enter to leave blank): ").strip()

    if ask_yes_no("Do you want to create a password?"):
        if ask_yes_no("Generate a password now?", True):
            generate_password()
            password = input("Password to save (paste or type it here): ")
        else:
            password = input("Password: ")

    if not username and not email and not password:
        print("Nothing to save.")
        return

    if not confirm("Save this entry to the unencrypted spreadsheet?"):
        print("Entry not saved.")
        return

    try:
        append_entry([site, username, email, password])
        print("Entry saved.")
    except Exception as error:
        print(f"Could not save the entry: {error}")


def choose_entry():
    try:
        entries = load_entries()
    except Exception as error:
        print(f"Could not read the vault: {error}")
        return None

    if not entries:
        print("No saved entries.")
        return None

    for number, (_, values) in enumerate(entries, start=1):
        print(f"{number}. {values[0]}")

    selection = read_int("Choose an entry number (0 to cancel): ", 0, len(entries))
    if selection == 0:
        return None
    return entries[selection - 1]


def view_entries():
    try:
        entries = load_entries()
    except Exception as error:
        print(f"Could not read the vault: {error}")
        return

    if not entries:
        print("No saved entries.")
        return

    for number, (_, values) in enumerate(entries, start=1):
        print(f"{number}. {values[0]}")

    selection = read_int("Choose an entry number (0 to cancel): ", 0, len(entries))
    if selection == 0:
        return
    if not confirm("Reveal the selected entry, including its password?"):
        print("Password not revealed.")
        return

    _, values = entries[selection - 1]
    print(f"\nSite or custom name: {values[0]}")
    print(f"Username: {values[1]}")
    print(f"Email: {values[2]}")
    print(f"Password: {values[3]}")


def edit_entry():
    selected = choose_entry()
    if selected is None:
        return

    row, original = selected
    values = original.copy()
    print("Press Enter to keep a value unchanged.")
    for index, label in enumerate(HEADERS):
        replacement = input(f"{label} [{values[index]}]: ")
        if replacement != "":
            values[index] = replacement

    if values == original:
        print("No changes made.")
        return

    try:
        entries = load_entries()
        for other_row, other_values in entries:
            if other_row != row and other_values[0].casefold() == values[0].casefold():
                print("Another entry already uses that site or custom name.")
                return
    except Exception as error:
        print(f"Could not validate the changes: {error}")
        return

    if not confirm("Save changes to this entry?"):
        print("Changes not saved.")
        return

    try:
        save_entry(row, values)
        print("Entry updated.")
    except Exception as error:
        print(f"Could not update the entry: {error}")


def remove_entry():
    selected = choose_entry()
    if selected is None:
        return
    row, values = selected
    if not confirm(f"Delete the entry for {values[0]!r}?"):
        print("Entry not deleted.")
        return
    try:
        delete_entry(row)
        print("Entry deleted.")
    except Exception as error:
        print(f"Could not delete the entry: {error}")


def main():
    show_warning()
    try:
        ensure_vault()
    except Exception as error:
        print(f"Could not create or open the vault: {error}")
        return

    while True:
        print("\n--- pixelpass ---")
        print("1. Generate password")
        print("2. Generate passphrase")
        print("3. Generate username")
        print("4. Create new password")
        print("5. View saved passwords")
        print("6. Edit saved password")
        print("7. Delete saved entry")
        print("0. Exit")
        choice = input("Enter the number of the action you want to do: ").strip()

        if choice == "1":
            generate_password()
        elif choice == "2":
            generate_passphrase()
        elif choice == "3":
            generate_username()
        elif choice == "4":
            create_new_entry()
        elif choice == "5":
            view_entries()
        elif choice == "6":
            edit_entry()
        elif choice == "7":
            remove_entry()
        elif choice == "0":
            print("Goodbye.")
            break
        else:
            print("Enter a number from 0 to 7.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nGoodbye.")
