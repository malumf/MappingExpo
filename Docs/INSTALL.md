<img width="1264" height="843" alt="image" src="https://github.com/user-attachments/assets/6f4db1bb-6d7b-4225-af92-31060c14989d" />

# 📦 MappingExpo — Installation Guide

-----

## 🔗 Download (Source)

Clone the repository:

```
git clone https://github.com/xPloits3c/DorkEye.git
```

Or download the latest release:
👉 [github.com/xPloits3c/DorkEye/releases](https://github.com/xPloits3c/DorkEye/releases/)

-----

## 📋 Table of Contents

1. [Prerequisites](#-prerequisites)
1. [Quick Installation (Recommended)](#-quick-installation-recommended)
1. [Termux / Android Installation](#-termux--android-installation)
1. [CLI Command Mode (Optional)](#-cli-command-mode-optional)
1. [Verification](#-verification)
1. [Project Structure](#-project-structure)
1. [Troubleshooting](#-troubleshooting)
1. [Updating MappingExpo](#-updating-mappingexpo)
1. [Uninstallation](#-uninstallation)
1. [Support](#-support)

-----

## 🔧 Prerequisites

|Required Software|Check Command      |
|-----------------|-------------------|
|Python 3.9+      |`python3 --version`|
|pip (latest)     |`pip3 --version`   |
|git              |`git --version`    |


> **Note:** `git` is only required for source installation. If you install via `pip install mappingexpo`, you only need Python and pip.

**System Requirements:**

- Linux / Windows 10+ / macOS 10.14+ / Android (Termux)
- 512 MB RAM minimum
- 100 MB free disk space
- Internet connection

**Key Python Dependencies** (installed automatically via `pip install mappingexpo` or `requirements.txt`):

- `ddgs` — DuckDuckGo search engine
- `requests` — HTTP client
- `rich` — Terminal formatting and progress bars
- `pyyaml` — Configuration and template parsing
- `urllib3` — Low-level HTTP

**Optional Dependencies** (for full feature support):

- `mappingexpo_agents.py` in `Tools/` — Enables `--analyze` and `--crawl` features
- `dork_generator.py` in `Tools/` — Enables `--dg` dork generator
- `http_fingerprints.json` — Enables HTTP fingerprint rotation

-----

## 🐧 Quick Installation 
This method works on **Linux**, **macOS**, and **Windows**.

```
# Clone the repository
git clone https://github.com/xPloits3c/DorkEye.git
cd MappingExpo

# Create virtual environment
python3 -m venv mappingexpo_env

# Activate virtual environment
# Linux / macOS:
source mappingexpo_env/bin/activate

# Windows:
# mappingexpo_env\Scripts\activate

# Upgrade pip
pip install --upgrade pip

# Install dependencies
pip install -r requirements.txt

# Verify installation
python mappingexpo.py -h
```

-----

## 📱 Termux / Android Installation

MappingExpo auto-detects Termux and activates battery-saver mode (reduced timeouts, fewer probe samples). No additional flags needed.

### From Source

```
# Install Python and git
pkg update && pkg upgrade
pkg install python git

# Clone and install
git clone https://github.com/xPloits3c/DorkEye.git
cd MappingExpo

# Create virtual environment (recommended to avoid Termux package conflicts)
python -m venv mappingexpo_env
source mappingexpo_env/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Run
python mappingexpo.py --wizard
```

💡 On Termux, MappingExpo automatically:

- Reduces connect timeouts (3s vs 4s)
- Lowers SQLi probe/boolean/time-based sample counts
- Displays a `Platform: Android / Termux ⚡ battery-saver active` badge in the banner

-----

## ✅ Verification

### From source:

```
# Show help and all available flags
python mappingexpo.py -h

# Create a sample config file
python mappingexpo.py --create-config

# Quick test search
python mappingexpo.py -d "python programming" -c 5 -o test.html

# Test dork generator (if templates are present)
python mappingexpo.py --dg=all --mode=soft -c 5 -o dg_test.html

# Launch the interactive wizard
python mappingexpo.py --wizard
```
-----

## 📁 Project Structure

```
MappingExpo/
├── mappingexpo.py                  # Main script
├── pyproject.toml              # PyPI package configuration
├── requirements.txt            # Python dependencies
├── setup.py                    # CLI install config (editable mode)
├── mappingexpo_config.yaml         # Config (generated with --create-config)
├── http_fingerprints.json      # Browser fingerprint profiles
├── Tools/
│   ├── dork_generator.py       # Dork Generator engine (--dg)
│   ├── mappingexpo_agents.py       # Analysis + Crawl agents (--analyze, --crawl)
│   ├── mappingexpo_analyze.py      # Standalone analysis script (executable directly)
│   └── mappingexpo_patterns.py     # Pattern matching utilities
├── Templates/
│   ├── dorks_templates.yaml    # Default dork templates
│   └── *.yaml                  # Additional template files
└── Dump/                       # Output folder (auto-created)
    ├── results.json
    ├── report.html
    └── ...
```

-----

## 🐛 Troubleshooting

### `ModuleNotFoundError: ddgs`

The search engine module has been renamed. Fix:

```
pip uninstall duckduckgo-search -y
pip install ddgs
```

### `Externally Managed Environment` (Kali Linux / Debian 12+)

Modern Debian-based systems block global pip installs. Use a virtual environment:

```
python3 -m venv mappingexpo_env
source mappingexpo_env/bin/activate
pip install -r requirements.txt
```

### Permission Errors

### `--templates=filename.yaml` syntax error

The `--templates` flag requires `=` syntax (no space):

```
# ✅ Correct
python mappingexpo.py --dg=sqli --templates=dorks_templates.yaml

# ❌ Wrong
python mappingexpo.py --dg=sqli --templates dorks_templates.yaml
```

### `mappingexpo_agents.py not found` warning

The `--analyze` and `--crawl` features require `mappingexpo_agents.py` in the `Tools/` directory. If missing, MappingExpo runs normally but these features are disabled. Ensure your clone is up to date:

```
git pull origin master
```

> **Note:** When installed via PyPI, the `Tools/` directory is not included. For full feature support (agents, dork generator), use the source installation.

### HTTP Fingerprinting disabled warning

If `http_fingerprints.json` is missing or malformed, MappingExpo falls back to basic User-Agent rotation. Re-download the file from the repository.

### SSL/TLS warnings

MappingExpo disables SSL verification for maximum compatibility during OSINT scanning. `InsecureRequestWarning` messages are suppressed automatically.

-----

## 🔄 Updating MappingExpo

### Source install:

```
cd MappingExpo
git pull origin master
pip install --upgrade -r requirements.txt
```
-----

## 🗑️ Uninstallation

```
rm -rf MappingExpo
```

**Windows:**

```
rmdir /s /q MappingExpo
```

**Remove only the virtual environment:**

```
rm -rf mappingexpo_env
```

**If installed in CLI mode (source):**

```
pip uninstall mappingexpo
```

-----

## 📞 Support

If you encounter issues, open an issue on GitHub:
👉 [github.com/xPloits3c/DorkEye/issues](https://github.com/xPloits3c/DorkEye/issues)

Please include:

- Operating system + version
- Python version (`python3 --version`)
- Installation method (PyPI or source)
- Full error message / traceback
- Steps to reproduce the issue
- Whether you’re using a virtual environment

-----

## ✅ Post-Installation Checklist

**Source install:**

- ✔ Python 3.9+
- ✔ Virtual environment active
- ✔ Dependencies installed (`pip install -r requirements.txt`)
- ✔ `python mappingexpo.py -h` shows help
- ✔ `python mappingexpo.py --create-config` creates config
- ✔ Test search works (`-d "test" -c 5 -o test.html`)
- ✔ Dork generator works (`--dg=all -c 5 -o dg_test.html`)
- ✔ Wizard launches (`--wizard`)

-----

## 🎯 Installation Complete

MappingExpo is ready! Happy hunting. 🔍
