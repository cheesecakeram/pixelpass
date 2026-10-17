# **pixelpass**

pixelpass is a small, local password manager that saves your entries in a spreadsheet. It’s made to keep its files in its own application folder and work without an internet connection. Specially designed for CLI lovers.

---
![image](https://github.com/cheesecakeram/pixelpass/blob/32e80dbaca3cc3cd444b8b91e7f7239f4b6a4fdb/screenshot1.png)
---

### What it can do

  Save password data in a spreadsheet.
 
  Encrypt saved data with a master password using scrypt and AES-GCM.

  Let you set, change, or remove the master password.

  Generate passwords and passphrases using an expanded word list.

  Clear the terminal after an operation, if you enable that setting.

  Create a launcher for your OS.

---

### Getting started

pixelpass requires Python and the cryptography and openpyxl libraries.

---

### Master password and your data

The master password encrypts saved data. If you forget it, you may not be able to recover your encrypted entries, so keep it somewhere safe. If you forget the master password, saved data may no longer be encrypted.

The spreadsheet and other pixelpass files should be treated as sensitive. Anyone who can access unencrypted files may be able to read the saved data.

---

### Why use pixelpass?

I don't know. 🥶
