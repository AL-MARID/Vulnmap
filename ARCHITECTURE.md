# Vulnmap Architecture Overview

Vulnmap is an advanced, AI-driven penetration testing tool designed with a modular and scalable architecture. The core design principles focus on separation of concerns, extensibility, and robust error handling.

## Core Components

The application is structured into the following main directories and components:

1.  **`vulnmap.py` (Main Entry Point):**
    *   Handles command-line argument parsing (`argparse`).
    *   Loads configuration (`ConfigLoader`).
    *   Initializes the `ScannerEngine` and `AIProviderManager`.
    *   Orchestrates the main scanning process (Reconnaissance, Crawling, Scanning).
    *   Manages reporting and final output display.

2.  **`core/` (Core Logic):**
    *   **`scanner_engine.py`:** The heart of the application. Manages the scanning workflow, including crawling, link extraction, and delegating vulnerability checks.
    *   **`vulnerability_scanner.py`:** Contains the logic for specific vulnerability checks (e.g., SQLi, XSS). It interacts with the `AIProviderManager` for AI-assisted payload generation and analysis.
    *   **`report_generator.py`:** Responsible for compiling scan results into final reports (e.g., HTML, PDF).

3.  **`utils/` (Utilities):**
    *   **`config_loader.py`:** Handles loading and validation of `config.yaml`.
    *   **`http_client.py`:** A wrapper around the `requests` library, providing session management, retry logic, and proxy support.
    *   **`logger.py`:** Centralized logging utility using the standard Python `logging` module.
    *   **`parser.py`:** Contains utilities for URL normalization, link extraction, and response analysis (`BeautifulSoup`).

4.  **`ai_providers/` (AI Integration):**
    *   **`provider_manager.py`:** Manages connections to various AI services (e.g., Gemini, OpenAI). It abstracts the AI API calls, allowing the core scanner to request AI assistance without knowing the underlying provider details.

## Data Flow

1.  **Initialization:** `vulnmap.py` loads `config.yaml` and initializes the `ScannerEngine`.
2.  **Reconnaissance:** The `ScannerEngine` uses `http_client.py` and `parser.py` to gather initial data (e.g., domain information, technology detection).
3.  **Crawling:** The `ScannerEngine` uses a queue-based approach with `http_client.py` to crawl the target up to the configured depth, using `parser.py` to extract new links.
4.  **Scanning:** The `VulnerabilityScanner` receives URLs and parameters. It uses the `AIProviderManager` to generate intelligent payloads or analyze responses, then uses `http_client.py` to test the payloads.
5.  **Reporting:** After the scan, the `ReportGenerator` processes the results and outputs the final report.

## Repository Information

*   **Source Code:** [https://github.com/AL-MARID/Vulnmap](https://github.com/AL-MARID/Vulnmap)
*   **Bug Reports:** [https://github.com/AL-MARID/Vulnmap/issues](https://github.com/AL-MARID/Vulnmap/issues)
