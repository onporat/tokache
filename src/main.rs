use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use clap::Parser;
use config::Config;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

#[derive(Parser, Debug)]
#[command(arg_required_else_help = true)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    /// Delete all cache files
    #[arg(long, default_value_t = false)]
    clean: bool,

    /// Command TTL
    #[arg(short, long)]
    ttl: Option<i64>,

    /// expiration JSON key
    #[arg(short, long)]
    expiration_key: Option<String>,

    command: Option<Vec<String>>,
}

fn main() -> Result<()> {
    let home_dir = dirs::home_dir().unwrap();
    let settings = Config::builder()
        .set_default(
            "cache_dir",
            home_dir.join(".cache/cacheme").display().to_string(),
        )?
        .add_source(
            config::File::with_name(
                &home_dir
                    .join(".local/config/cacheme/settings")
                    .display()
                    .to_string(),
            )
            .required(false),
        )
        .add_source(config::Environment::with_prefix("CACHEME"))
        .build()
        .unwrap();

    let mut cli = Cli::parse();

    let cache_dir = &settings
        .get::<PathBuf>("cache_dir")
        .context("Failed to get cache_dir config.")?;
    fs::create_dir_all(cache_dir).context(format!("Failed to create config_dir {cache_dir:?}"))?;

    if cli.clean {
        for entry in fs::read_dir(cache_dir)
            .context(format!("Failed to read files from dir {cache_dir:?}"))?
        {
            let file = entry.unwrap().path();
            if file.is_file() {
                fs::remove_file(&file).context(format!("Failed to delete cache file {file:?}"))?;
            }
        }
        return Ok(());
    }

    // You can check the value provided by positional arguments, or option arguments
    let command = cli
        .command
        .as_deref()
        .ok_or_else(|| anyhow!("Command is empty"))?;

    // default command
    if cli.ttl.is_none()
        && cli.expiration_key.is_none()
        && is_command_included(
            command,
            ["aws", "eks", "get-token"].map(String::from).as_ref(),
        )
    {
        cli.expiration_key = Some(String::from(".status.expirationTimestamp"))
    }

    let cmd_md5 = compute_md5(command);

    let cache_file = cache_dir.join(cmd_md5);

    if cache_file.exists() {
        let now = Utc::now();
        if let Some(ttl) = cli.ttl {
            let meta =
                fs::metadata(&cache_file).context("Failed to get metadata of file {cache_file}")?;
            if !is_ttl_expiered(meta, ttl, now)? {
                let output = fs::read_to_string(&cache_file)
                    .context("Failed to read contect of file {cache_file}")?;
                print!("{output}");
                return Ok(());
            }
        } else if let Some(expiration_key) = cli.expiration_key {
            let json = fs::read_to_string(&cache_file)
                .context(format!("Failed to read contect of file {cache_file:?}"))?;
            if !is_json_expiered(&json, &expiration_key, now)? {
                print!("{json}");
                return Ok(());
            }
        }
    }

    if cache_file.exists() {
        fs::remove_file(&cache_file)
            .context(format!("Failed to delete cache file {cache_file:?}"))?;
    }

    let output =
        execute_command(command).context(format!("Failed to execute command {command:?}"))?;
    fs::write(&cache_file, &output).context(format!("Failed to write to file {cache_file:?}"))?;

    print!("{output}");
    Ok(())
}

fn compute_md5(command: &[String]) -> String {
    let command_line = command.join(" ");
    let digest = md5::compute(command_line.as_bytes());
    format!("{:x}", digest)
}

fn execute_command(command: &[String]) -> Result<String> {
    let output = Command::new(&command[0]).args(&command[1..]).output()?;
    if !output.status.success() {
        return Err(anyhow::anyhow!("Command returned non zero status code"));
    }

    let stdout = String::from_utf8(output.stdout)?;
    Ok(stdout)
}

fn is_ttl_expiered(file_meta: fs::Metadata, ttl: i64, now: DateTime<Utc>) -> Result<bool> {
    let modified_time = file_meta.modified().map(DateTime::<Utc>::from)?;
    let sec_diff = (now - modified_time).num_seconds();
    Ok(sec_diff > ttl)
}

fn is_json_expiered(json: &str, key: &str, now: DateTime<Utc>) -> Result<bool> {
    let jq_key = if key.starts_with('.') {
        String::from(key)
    } else {
        format!(".{key}")
    };
    let binding = j9::run(&jq_key, json).context("Failed to parse json")?;
    let value_with_quotes = binding
        .first()
        .ok_or_else(|| anyhow!("Failed to get json key"))?;
    let date_str = &value_with_quotes[1..value_with_quotes.len() - 1];
    let expiration =
        dateparser::parse(date_str).context(format!("Failed to parse date {date_str}"))?;
    Ok(now >= expiration)
}

fn is_command_included(command: &[String], pattern: &[String]) -> bool {
    if pattern.is_empty() || pattern.len() > command.len() {
        return false;
    }
    if pattern[0] != command[0] {
        return false;
    }
    let mut p = 1;
    for c in command.iter().skip(1) {
        if p < pattern.len() && c == &pattern[p] {
            p += 1;
        }
    }

    p == pattern.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_command_included() {
        let command = vec![
            "one".to_string(),
            "two".to_string(),
            "three".to_string(),
            "four".to_string(),
        ];

        // Test with a pattern that exists in the command.
        assert!(is_command_included(
            &command,
            &["one".to_string(), "two".to_string(),]
        ));
        assert!(is_command_included(
            &command,
            &["one".to_string(), "three".to_string(),]
        ));

        // Test with a pattern that doesn't exist in the command.
        assert!(!is_command_included(
            &command,
            &["one".to_string(), "five".to_string(),]
        ));
        assert!(!is_command_included(
            &command,
            &["two".to_string(), "three".to_string(),]
        ));

        // Test when pattern is empty
        let pattern = vec!["".to_string()];
        assert!(!is_command_included(&command, &pattern));

        // Test when command is empty
        let command = Vec::<String>::new();
        let pattern = vec!["one".to_string(), "two".to_string()];
        assert!(!is_command_included(&command, &pattern));

        // Test when both command and pattern are empty
        assert!(!is_command_included(
            &Vec::<String>::new(),
            &Vec::<String>::new()
        ));
    }

    #[test]
    fn test_is_json_expiered() {
        let json = r#"{
            "kind": "ExecCredential",
            "apiVersion": "client.authentication.k8s.io/v1beta1",
            "spec": {},
            "status": {
              "expirationTimestamp": "2019-08-14T18:44:27Z",
              "token": "k8s-aws-v1EXAMPLE_TOKEN_DATA_STRING..."
            }
          }"#;
        let key = ".status.expirationTimestamp";
        let after = dateparser::parse("2020-08-14T18:44:27Z").unwrap();
        assert!(is_json_expiered(json, key, after).is_ok());
        assert!(is_json_expiered(json, key, after).unwrap());

        let key_without_prefix = "status.expirationTimestamp";
        assert!(is_json_expiered(json, key_without_prefix, after).is_ok());
        assert!(is_json_expiered(json, key_without_prefix, after).unwrap());

        let before = dateparser::parse("2018-08-14T18:44:27Z").unwrap();
        assert!(is_json_expiered(json, key, before).is_ok());
        assert!(!is_json_expiered(json, key, before).unwrap());

        let missing_key = "missing_key";
        assert!(is_json_expiered(json, missing_key, after).is_err());
    }
}
