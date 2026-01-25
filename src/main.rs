use clap::Parser;
use colored::*;
use regex::Regex;
use std::fs;
use walkdir::WalkDir;
use rayon::prelude::*;

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

// Define struct to hold scan results
#[derive(Clone)]
struct Finding{
    file: String,
    line_num: usize,
    rule_name: String,
    severity: String,
    code_snippet: String,
}

fn main() {
    // Parse arguments
    let args = Cli::parse();

    println!("{}", format!("Starting scan (parallel) on: {}", args.path).blue().bold());

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

    // Parallel walk + scan; collect findings
    let findings: Vec<Finding> = WalkDir::new(&args.path)
        .into_iter()
        .par_bridge() // convert to a parallel iterator
        .filter_map(|e| e.ok())
        .filter(|entry| entry.path().is_file())
        .filter(|entry| {
            entry
                .path()
                .extension()
                .map(|ext| {
                    let ext_str = ext.to_string_lossy();
                    ext_str == "php" || ext_str == "js"
                })
                .unwrap_or(false)
        })
        .map(|entry| {
            let path_str = entry.path().to_string_lossy().to_string();
            scan_file_collect(&path_str, &rules)
        })
        .flatten()
        .collect();

    // Print in a deterministic, sequential way
    if findings.is_empty() {
        println!("{}", "No findings detected.".green().bold());
    } else {
        for f in &findings {
            print_finding(f);
        }
        println!(
            "{} {}",
            "Total findings:".bold(),
            findings.len().to_string().yellow().bold()
        );
    }
}

// The function that actually reads the file and checks regex
fn scan_file_collect(filepath: &str, rules: &[Rule]) -> Vec<Finding> {
    let content = match fs::read_to_string(filepath) {
        Ok(c) => c,
        Err(_) => return vec![], // Skip unreadable files (binary/permissions)
    };

    let mut findings = Vec::new();

    for (line_num, line) in content.lines().enumerate() {
        for rule in rules {
            if rule.pattern.is_match(line) {
                findings.push(Finding {
                    file: filepath.to_string(),
                    line_num: line_num + 1,
                    rule_name: rule.name.clone(),
                    severity: rule.severity.clone(),
                    code_snippet: line.trim().to_string(),
                });
            }
        }
    }

    findings
}

// A simple pretty-printer for our results
fn print_finding(f: &Finding) {
    let color_severity = match f.severity.as_str() {
        "CRITICAL" => "CRITICAL".red().bold(),
        "HIGH" => "HIGH".red(),
        _ => "MEDIUM".yellow(),
    };

    println!("--------------------------------------------------");
    println!("{} Found: {}", color_severity, f.rule_name);
    println!("File: {}:{}", f.file, f.line_num);
    println!("Code: {}", f.code_snippet.trim());
}