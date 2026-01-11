# 🦀 Rust Simple SAST Tool

A lightweight **Static Application Security Testing (SAST)** CLI tool written in Rust. This tool scans local codebases (specifically PHP and JavaScript files) for dangerous function calls and potential hardcoded secrets using Regex pattern matching.

**Status:** *Active Learning Project / MVP*

## 🚀 Features (The Basics)
Currently, the tool includes the following functionality:

-   **CLI Interface:** Built with `clap` to easily accept path arguments.
-   **File Traversal:** Recursively walks through directory trees using `walkdir`.
-   **Pattern Matching:** Uses Rust's `regex` crate to identify security flaws.
-   **Visual Output:** Colored terminal output to highlight high-severity findings.

### Default Rules
The tool currently checks for:
-   **RCE Risks:** `eval()`, `exec()`, `system()`, `passthru()`.
-   **Hardcoded Secrets:** Generic patterns for API keys (e.g., `AWS_ACCESS_KEY`).

## 🛠️ Getting Started

### Prerequisites
-   [Rust and Cargo](https://www.rust-lang.org/tools/install) installed.

### Installation
Clone the repository:
```bash
git clone https://github.com/yourusername/rust-sast-tool.git
cd rust-sast-tool
```

### Usage
Run the tool using `cargo`, passing the directory you want to scan as an argument:

```bash
# Scan the current directory
cargo run -- .

# Scan a specific project path
cargo run -- ./path/to/vulnerable-app
```

## 🏗️ Project Structure
This project was built to learn Rust fundamentals. Key concepts used include:

-   **Structs & Impl:** defining the `Rule` and `Cli` logic.
-   **Vectors (`Vec`):** Storing lists of active security rules.
-   **Error Handling:** Using `Result` and `Option` for file reading operations.
-   **External Crates:** Integrating community standard libraries (`clap`, `regex`, `colored`).

## 🔮 Roadmap (Next Steps)

The following features are planned to improve the tool and increase Rust proficiency:

### 1. Configuration Files (Intermediate)
**Goal:** Move rules out of `main.rs` and into a config file (YAML or TOML).
-   *Learning:* File serialization/deserialization with `serde` and `serde_yaml`.

### 2. Ignore Support (Intermediate)
**Goal:** Respect `.gitignore` files or allow a `.sastignore` file to skip `node_modules` or `vendor` folders.
-   *Learning:* String manipulation and filtering logic within iterators.

### 3. JSON/SARIF Output (Advanced)
**Goal:** Output results in JSON or SARIF (Static Analysis Results Interchange Format) so it can be used in GitHub Actions or CI/CD pipelines.
-   *Learning:* Structured data formatting and standard outputs.

### 4. Performance Optimization (Advanced)
**Goal:** Scan files in parallel.
-   *Learning:* Multi-threading using the `rayon` crate to parallelize the file walking iterator.

### 5. Abstract Syntax Trees (Expert)
**Goal:** Move beyond Regex (which is brittle) to parsing code structure.
-   *Learning:* Using parsers like `tree-sitter` to understand the code context (e.g., distinguishing between a comment and actual code).

## 🤝 Contributing
This is a personal learning project, but suggestions are welcome!

## 📄 License
MIT