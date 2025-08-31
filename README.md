# SolanaSecToolkit

SolanaSecToolkit is a Rust-based security analysis toolkit for Solana smart contracts.  
It provides static analysis, fuzz testing, and interactive reporting to help developers identify vulnerabilities before deployment.

---

## Features
- **Static Analysis**: Detects critical vulnerabilities with high accuracy.  
- **Fuzz Testing**: Automated fuzzing of Solana programs.  
- **Interactive Reports**: HTML, JSON, Markdown, and CSV outputs with actionable suggestions.  
- **Severity Classification**: Critical, High, Medium, Low severity levels.  
- **Plugin System**: Extendable with custom security rules.  
- **CI/CD Integration**: GitHub Actions support and pre-commit hooks.  
- **Parallel Processing**: Multi-core analysis using Rust's `rayon` for high performance.  

---

## Installation

### From Crates.io
```bash
cargo install solsec
