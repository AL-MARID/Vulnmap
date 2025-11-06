# Vulnmap: AI-Driven Vulnerability Scanner and Mapping Tool

**Vulnmap** is an advanced, AI-driven penetration testing tool designed to automate the process of vulnerability scanning and network mapping. It leverages the power of large language models (LLMs) to enhance payload generation, response analysis, and overall scanning efficiency.

## Features

*   **AI-Assisted Scanning:** Utilizes LLMs for intelligent payload generation and analysis of complex vulnerabilities.
*   **Comprehensive Reconnaissance:** Includes modules for domain information gathering, technology detection, and initial mapping.
*   **Modular Design:** Easy to extend with new vulnerability checks and AI providers.
*   **Detailed Reporting:** Generates clear and actionable reports (HTML, PDF).
*   **Configurable:** Highly customizable via `config/config.yaml`.

## Quickstart

### Prerequisites

*   Python 3.8+
*   A valid API key for an AI provider (e.g., Gemini, OpenAI) configured in `config/config.yaml`.

### Installation

```bash
# Clone the repository
git clone https://github.com/AL-MARID/Vulnmap.git
cd Vulnmap

# Install dependencies
pip3 install -r requirements.txt
```
### Configure AI providers:
```bash
cp config/config.example.yaml config/config.yaml
# Edit config.yaml with your API keys
```
## Running a Scan

Before running a scan, you can view all available command-line options:

```bash
python3 vulnmap.py -h
```

Run a scan against your target:

```bash
python3 vulnmap.py -u https://your-target-website.com
```

## Contributing

Contributions are welcome! If you have suggestions for improvements, new features, or bug fixes, please feel free to:

1.  **Fork the repository.**
2.  **Create a new branch** (`git checkout -b feature/YourFeature`).
3.  **Make your changes and commit them** (`git commit -m 'Add some feature'`).
4.  **Push to the branch** (`git push origin feature/YourFeature`).
5.  **Open a Pull Request.**

## License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.
