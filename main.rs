use colored::*;
use reqwest::blocking::Client;
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::process;
use url::Url;

fn find_redirect_param(url: &str) -> Option<String> {
    if url.contains("redirect=") {
        return Some("redirect".to_string());
    }

    let parsed_url = Url::parse(url).ok()?;
    let query_params: HashMap<_, _> = parsed_url.query_pairs().collect();

    query_params
        .keys()
        .find(|&param| {
            let lower_param = param.to_lowercase();
            ["redirect", "url", "target", "link", "goto", "target_url"]
                .iter()
                .any(|word| lower_param.contains(word))
        })
        .map(|param| param.to_string())
}

fn test_redirect(base_url: &str, payload: &str, redirect_param: &str, log_output: bool) {
    let client = Client::new();

    let mut parsed_url = Url::parse(base_url).unwrap();
    let full_url = if !redirect_param.is_empty() {
        if base_url.ends_with('=') {
            format!("{}{}", base_url, payload)
        } else {
            parsed_url.query_pairs_mut().append_pair(redirect_param, payload);
            parsed_url.to_string()
        }
    } else {
        let mut path = parsed_url.path().to_string();
        path.push_str(payload);
        parsed_url.set_path(&path);
        parsed_url.to_string()
    };

    if log_output {
        println!("{}", format!("Testing: {}", full_url).cyan());
    }

    match client.get(&full_url).send() {
        Ok(response) => {
            if (301..=308).contains(&response.status().as_u16()) {
                if let Some(location) = response.headers().get("Location") {
                    let location_str = location.to_str().unwrap_or("");
                    let parsed_base = Url::parse(base_url).unwrap();
                    let parsed_location = Url::parse(location_str).unwrap_or_else(|_| parsed_base.clone());

                    if parsed_location.domain().is_some() && parsed_location.domain() != parsed_base.domain() {
                        if log_output {
                            println!("{}", format!("[VULNERABLE] Redirects to: {}", location_str).red().bold());
                        }
                        let mut file = OpenOptions::new()
                            .append(true)
                            .create(true)
                            .open("vulnerable_urls.txt")
                            .unwrap();
                        writeln!(file, "Vulnerable URL: {}\nRedirects to: {}\n", full_url, location_str).unwrap();
                    } else if log_output {
                        println!(
                            "{}",
                            format!(
                                "[NOT VULNERABLE] Redirects within the same domain or relative path: {}",
                                location_str
                            )
                            .green()
                        );
                    }
                }
            } else if log_output {
                println!(
                    "{}",
                    format!("[NOT VULNERABLE] Does not redirect. Status code: {}", response.status()).yellow()
                );
            }
        }
        Err(e) => {
            if log_output {
                println!("{}", format!("[ERROR] Failed to test: {}", e).red());
            }
        }
    }

    if log_output {
        println!();
    }
}

fn read_payloads(filename: &str) -> io::Result<Vec<String>> {
    let file = File::open(filename)?;
    let reader = BufReader::new(file);
    Ok(reader.lines().filter_map(|line| line.ok()).filter(|line| !line.is_empty()).collect())
}

fn main() {
    println!("{}", "Open Redirect Scanner".cyan().bold());
    println!("{}\n", "=".repeat(50).cyan());

    let mut input = String::new();
    print!("{}", "Enter the base URL to test (e.g., https://example.com/page?redirect=): ".green());
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut input).unwrap();
    let base_url = input.trim().to_string();

    if !base_url.starts_with("http://") && !base_url.starts_with("https://") {
        println!("{}", "Invalid URL. Please include the protocol (http:// or https://)".red());
        process::exit(1);
    }

    input.clear();
    print!("{}", "Enter the name of the payloads file: ".green());
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut input).unwrap();
    let payloads_file = input.trim().to_string();

    input.clear();
    print!("{}", "Do you want to log outputs to console? (y/n): ".green());
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut input).unwrap();
    let log_output = input.trim().to_lowercase() == "y";

    let mut redirect_param = find_redirect_param(&base_url).unwrap_or_default();
    if redirect_param.is_empty() {
        input.clear();
        print!("{}", "No redirect parameter detected. Please enter a custom parameter to use: ".yellow());
        io::stdout().flush().unwrap();
        io::stdin().read_line(&mut input).unwrap();
        redirect_param = input.trim().to_string();
    }

    if log_output {
        println!(
            "\n{}",
            format!(
                "Scanning {} for open redirects using parameter '{}'...\n",
                base_url, redirect_param
            )
            .cyan()
        );
    }

    let payloads = match read_payloads(&payloads_file) {
        Ok(p) => p,
        Err(e) => {
            println!("{}", format!("Error reading file {}: {}", payloads_file, e).red());
            process::exit(1);
        }
    };

    File::create("vuln.txt").unwrap();

    let total_payloads = payloads.len();
    for (index, payload) in payloads.iter().enumerate() {
        if log_output {
            println!("{}", format!("Testing payload {}/{}", index + 1, total_payloads).cyan());
        }
        test_redirect(&base_url, payload, &redirect_param, log_output);
    }

    println!(
        "\n{}",
        "Scan complete! Check vulnerable_urls.txt for vulnerable URLs.".cyan()
    );
}
