use clap::Parser;
use colored::*;
use std::fs;
use regex::Regex;
use walkdir::WalkDir;

// Command line argument structure
#[derive(Parser)]
#[command(author, version, about, long_about = None
)]