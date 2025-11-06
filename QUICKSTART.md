# Vulnmap Quickstart Guide

Welcome to **Vulnmap**, the AI-Driven Vulnerability Scanner and Mapping Tool. This guide will help you get started quickly.

## 1. Prerequisites

*   **Python:** Python 3.8 or higher is required.
*   **AI API Key:** Vulnmap relies on AI providers (like Gemini or OpenAI) for advanced features. You must have a valid API key configured in `config/config.yaml`.

## 2. Installation

Clone the repository and install the required dependencies:

```bash
# Clone the repository
git clone https://github.com/AL-MARID/Vulnmap.git
cd Vulnmap

# Install dependencies
pip3 install -r requirements.txt
```

## 3. Configuration

The main configuration file is `config/config.yaml`. You must edit this file to set your AI provider key and define your scan parameters.

**Example Configuration Snippet:**

```yaml
ai_providers:
  gemini:
    enabled: true
    api_key: "YOUR_GEMINI_API_KEY_HERE" # REQUIRED
    model: "gemini-2.5-flash"
    temperature: 0.7
    max_tokens: 2000

scanner:
  target_url: "https://example.com" # Default target if not specified via CLI
  default_depth: 2                 # How deep the crawler should go
  default_threads: 5               # Number of concurrent threads
  enable_recon: true               # Enable reconnaissance modules
```

## 4. Running a Scan

You can run Vulnmap using the command-line interface (CLI).

### Basic Scan

Run a scan against a target URL specified directly in the command:

```bash
python3 vulnmap.py -u https://your-target-website.com
```

### Scan with Configuration

Run a scan using the target URL defined in your `config/config.yaml`:

```bash
python3 vulnmap.py
```

### Verbose Mode

Use the `-v` flag to enable verbose output for detailed debugging information:

```bash
python3 vulnmap.py -u https://your-target-website.com -v
```

## 5. Reporting

Scan results are automatically saved to the `reports/` directory in the format specified in `config.yaml` (default is HTML).

## Support and Issues

If you encounter any issues or have suggestions, please report them on the official GitHub repository:

*   **GitHub Issues:** [https://github.com/AL-MARID/Vulnmap/issues](https://github.com/AL-MARID/Vulnmap/issues)
*   **Source Code:** [https://github.com/AL-MARID/Vulnmap](https://github.com/AL-MARID/Vulnmap)
