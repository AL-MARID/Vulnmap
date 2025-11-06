```
Vulnmap/
│
├── vulnmap.py                 # Main entry point
├── setup.py                    # Installation setup
├── requirements.txt            # Python dependencies
├── README.md                   # Project documentation
├── QUICKSTART.md              # Quick start guide
├── CONTRIBUTING.md            # Contributing guidelines
├── CHANGELOG.md               # Version history
├── LICENSE                    # MIT License
├── .gitignore                 # Git ignore rules
├── install.ps1                # Windows installation script
├── install.sh                 # Linux/Mac installation script
│
├── core/                      # Core functionality
│   ├── __init__.py
│   ├── scanner_engine.py      # Main scanning orchestrator
│   ├── ai_payload_generator.py # AI-powered payload generation
│   ├── vulnerability_scanner.py # Vulnerability detection
│   └── report_generator.py    # Report creation
│
├── ai_providers/              # AI provider integrations
│   ├── __init__.py
│   ├── provider_manager.py    # Provider management
│   ├── openai_provider.py     # OpenAI/GPT-4 integration
│   ├── claude_provider.py     # Anthropic Claude integration
│   ├── grok_provider.py       # xAI Grok integration
│   └── ollama_provider.py
│   └── gemini.py
  # OLLAMA local LLM integration
│
├── modules/                   # Security testing modules
│   ├── __init__.py
│   └── reconnaissance/        # OSINT & enumeration
│       ├── __init__.py
│       └── recon_engine.py
│
├── utils/                     # Utility functions
│   ├── __init__.py
│   ├── logger.py             # Logging utilities
│   ├── config_loader.py      # Configuration management
│   ├── http_client.py        # HTTP client with retry logic
│   └── parser.py             # URL and response parsing
│
├── config/                    # Configuration files
│   └── config.example.yaml   # Example configuration
│
├── templates/                 # Report templates
│   └── (HTML/PDF templates)
│
├── examples/                  # Usage examples
│   └── basic_usage.py        # Basic usage example
│
├── logs/                      # Log files (auto-created)
├── data/                      # Database files (auto-created)
└── reports/                   # Generated reports (auto-created)
```
- Orchestrates the entire penetration testing process
- Multi-threaded web crawling
- URL discovery and management
- Coordinates vulnerability scanning
- Manages scan lifecycle
- Generates intelligent, context-aware payloads
- Integrates with multiple AI providers
- CVE-aware payload generation
- Framework-specific attack vectors
- Adaptive payload mutation
- Implements 25+ vulnerability detection methods
- SQL Injection (Error, Blind, Time-based)
- XSS (Reflected, Stored, DOM)
- Command Injection
- SSRF, XXE, Path Traversal
- CSRF, Open Redirect
- Security misconfigurations
- Professional report generation
- Multiple formats (HTML, PDF, JSON)
- Executive summaries
- Severity-based classification
- Remediation recommendations
- Dynamic provider switching
- Unified interface for all AI providers
- Failover and retry logic
- API key management
- **OpenAI**: GPT-4o integration
- **Claude**: Anthropic Claude 3.5 Sonnet
- **Grok**: xAI Grok Beta
- **OLLAMA**: Local LLM support
- DNS enumeration
- WHOIS lookup
- Subdomain discovery
- Technology detection
- SSL certificate analysis
- Port scanning
- Centralized logging
- File and console output
- Log rotation
- Severity levels
- YAML configuration management
- Environment variable support
- Default configurations
- Validation
- Robust HTTP client
- Automatic retries
- Proxy support
- Custom headers/cookies
- SSL verification
- URL parsing and normalization
- HTML content extraction
- Form detection
- Technology fingerprinting
- Link extraction
```
User Input → Scanner Engine → Web Crawler → URL Discovery
                ↓
        AI Payload Generator ← AI Provider
                ↓
    Vulnerability Scanner → HTTP Client → Target
                ↓
        Results Collection
                ↓
        Report Generator → Output (HTML/PDF/JSON)
```
All settings are managed through `config/config.yaml`:
- AI provider credentials
- Scanner parameters
- Vulnerability checks
- Reconnaissance modules
- Report settings
- Logging configuration
1. Add check method to `vulnerability_scanner.py`
2. Register in enabled_checks
3. Update documentation
1. Create provider class in `ai_providers/`
2. Implement `generate()` method
3. Register in `provider_manager.py`
4. Update configuration
1. Create template in `templates/`
2. Add generator method in `report_generator.py`
3. Update CLI options
- Always activate virtual environment
- Keep dependencies updated
- Use configuration files for settings
- Never commit API keys
- Test on authorized targets only
- Follow ethical hacking guidelines
