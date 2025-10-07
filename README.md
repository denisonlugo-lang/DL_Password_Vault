# 🔐 DL Password Vault

![Python](https://img.shields.io/badge/Python-3.11-blue)
![GUI](https://img.shields.io/badge/GUI-Tkinter-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-success)

A **secure, voice-enabled password manager** built in **Python** using **Tkinter**, designed for simplicity, usability, and modern functionality.  
Includes encryption, auto-lock, export/import, dark mode, and an **AI-powered local assistant** for voice and text guidance.

---

## 🧭 Overview

DL Password Vault is a desktop application designed to help users **securely store and manage passwords** in an intuitive, AI-assisted environment.  
It uses **AES encryption** for local security, an **auto-lock timer** for protection during inactivity, and an **AI assistant** that guides users through security best practices — via both text and voice.

---

## ✨ Features

| Feature | Description |
|----------|-------------|
| 🔒 **Master Password Protection** | Access your vault securely with a hashed master key |
| 🧠 **AI Assistant** | Built-in local AI assistant for security tips and app help |
| 🎙️ **Voice Input** | Add or search entries using speech recognition |
| 🗣️ **Text-to-Speech** | Assistant can verbally respond to queries |
| 🌓 **Theme Modes** | Toggle between light and dark modes |
| 💾 **Export & Import Vaults** | Backup or restore your encrypted password database |
| ⏱️ **Auto Lock Timer** | Customizable inactivity lock for enhanced security |
| 🧰 **Settings Panel** | Manage preferences (theme, voice, lock duration, etc.) |
| 🖼️ **Branding** | Personalized DL logo and splash screen for professional UI |

---

## 🧩 Tech Stack

- **Language:** Python 3.11  
- **UI Framework:** Tkinter  
- **Encryption:** Cryptography (AES / Fernet)  
- **Voice Recognition:** SpeechRecognition + PyAudio  
- **Text-to-Speech:** pyttsx3  
- **Packaging:** PyInstaller (for creating `.exe`)  

---

## 🚀 Installation

### 1️⃣ Clone the repository
```bash
git clone https://github.com/denisonlugo-lang/DL_Password_Vault.git
cd DL_Password_Vault
