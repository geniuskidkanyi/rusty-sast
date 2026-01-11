use clap::Parser;
use colored::*;
use regex::Regex;
use std::fs;
use walkdir::WalkDir;

// 1. Define the Command Line Arguments structure
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// The path to the codebase to scan
    path: String,
}

// 2. Define a struct for a Security Rule
struct Rule {
    name: String,
    pattern: Regex, // The compiled regex pattern
    severity: String,
}

impl Rule {
    // A helper to create new rules easily
    fn new(name: &str, regex_str: &str, severity: &str) -> Self {
        Rule {
            name: name.to_string(),
            pattern: Regex::new(regex_str).expect("Invalid Regex"),
            severity: severity.to_string(),
        }
    }
}
fn main() {
    // Parse arguments
    let args = Cli::parse();

    println!("{}", format!("Starting scan on: {}", args.path).blue().bold());

    // Initialize Rules
    // NOTE: In regex, we escape special characters. 
    // `r""` is a "raw string" in Rust, so we don't need to double escape backslashes.
    let rules = vec![
        // Dangerous Functions
        Rule::new("Dangerous Eval", r"eval\(", "HIGH"),
        Rule::new("Dangerous Exec", r"exec\(", "HIGH"),
        Rule::new("System Command", r"system\(", "HIGH"),
        
        // Secrets / API Keys (Simplified patterns)
        Rule::new("AWS Access Key", r"AKIA[0-9A-Z]{16}", "CRITICAL"),
        Rule::new("Generic API Key", r#"api_key\s*=\s*['"][a-zA-Z0-9]{20,}['"]"#, "HIGH"),
        Rule::new("Hardcoded Password", r#"password\s*=\s*['"][a-zA-Z0-9@#$%]{6,}['"]"#, "MEDIUM"),
    ];

    // Walk the directory
    for entry in WalkDir::new(&args.path).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();

        // 1. Check if it's a file (not a directory)
        if !path.is_file() {
            continue;
        }

        // 2. Check extensions (PHP or JS)
        if let Some(extension) = path.extension() {
            let ext_str = extension.to_string_lossy();
            if ext_str != "php" && ext_str != "js" {
                continue; 
            }
        } else {
            continue;
        }

        // 3. Read the file content
        // verify_file is a helper function we will write next
        scan_file(path.to_str().unwrap(), &rules);
    }
}

// The function that actually reads the file and checks regex
fn scan_file(filepath: &str, rules: &Vec<Rule>) {
    // Try to read the file to a string
    let content = match fs::read_to_string(filepath) {
        Ok(c) => c,
        Err(_) => return, // If we can't read it (binary, permissions), just skip
    };

    // Iterate over lines to give line numbers in report
    for (line_num, line) in content.lines().enumerate() {
        for rule in rules {
            if rule.pattern.is_match(line) {
                print_finding(filepath, line_num + 1, rule, line);
            }
        }
    }
}

// A simple pretty-printer for our results
fn print_finding(file: &str, line_num: usize, rule: &Rule, code_snippet: &str) {
    let color_severity = match rule.severity.as_str() {
        "CRITICAL" => "CRITICAL".red().bold(),
        "HIGH" => "HIGH".red(),
        _ => "MEDIUM".yellow(),
    };

    println!("--------------------------------------------------");
    println!("{} Found: {}", color_severity, rule.name);
    println!("File: {}:{}", file, line_num);
    println!("Code: {}", code_snippet.trim());
}