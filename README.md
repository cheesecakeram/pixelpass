# pixelpass
https://github.com/cheesecakeram/pixelpass/blob/9781a952b61f760e8ac09e8429c4ee85fe464db2/screenshot1.png
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
