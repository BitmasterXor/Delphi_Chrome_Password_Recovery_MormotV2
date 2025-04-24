<h1 align="center">Delphi Google Chrome Browser Login Password Viewer</h1>
<p align="center">
  A Delphi application to retrieve, decrypt, and display login data from a Google Chrome browser's SQLite database.
</p>
<p align="center">
  <img src="Preview.png">
</p>

---

## ⚠️ Compatibility Warning
**IMPORTANT**: This project is designed for Chrome versions prior to Chrome 127. Starting with Chrome 127 (released in July 2024), Google implemented App-Bound Encryption (ABE) which prevents external applications from directly accessing and decrypting Chrome's sensitive data.

For newer Chrome versions, you would need to:
1. Use process injection techniques to access the encryption key from within Chrome's process context
2. Utilize Chrome's IElevator COM service to decrypt the data
3. Handle the new encryption format and storage methods

The sample code provided in this repository works only with Chrome versions 126 and earlier.

## 📋 Features
- **Retrieve Browser Data**: Fetch login data from the browser's SQLite database.
- **Decrypt Passwords**: Use Windows Cryptography API to decrypt stored passwords.
- **Display Data**: Show URL, username, and decrypted password in a `TListView`.
- **Clear Existing Items**: Automatically clears the `ListView` before loading new items.

## 🔍 Overview
- **Button1Click**: Handles data retrieval, decryption, and populating the `ListView`.
- **FormResize**: Repaints the `ListView` when the form is resized.
- **dpApiUnprotectData**: Utilizes the Windows Cryptography API to decrypt sensitive data.
- **GetLoggedInUserName**: Retrieves the current logged-in Windows username.

## 🛠️ Requirements
- **Delphi RAD Studio**
- **FireDAC Components** (Should already come pre-installed with your IDE so not really a requirement)
- **Mormot V2 Library** You can search it on google or just get it here: https://github.com/synopse/mORMot2

## 📜 License
This project is freeware provided as is, use at your own risk for your own research purposes!

## 📧 Contact
Discord: BitmasterXor

<p align="center">Made with ❤️ by: BitmasterXor and Friends, using Delphi RAD Studio</p>
