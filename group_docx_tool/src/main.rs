use std::{fmt::Write as _, fs, process::ExitCode, time::Duration};

use anyhow::{Context, bail};
use docx_rust::{Docx, DocxFile, document::Paragraph};
use hex::encode;
use purecrypto::hash::{Digest, Sha256};
use rand::{SeedableRng, rngs::SmallRng, seq::IndexedRandom};
use ureq::Agent;

mod config;

const KEY_WORD_COUNT: usize = 16;
const HASH_HEX_LEN: usize = 64;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> anyhow::Result<()> {
    let words = fetch_wordlist()?;
    let mut rng_cheap = SmallRng::from_rng(&mut rand::rng());

    for group in config::GROUPS {
        let file_name = format!("Group {group} Important Document.docx");
        let hash = group_hash(group);
        if fs::metadata(&file_name).is_ok() {
            verify_docx(&file_name, &hash)?;
        } else {
            create_docx(&file_name, &hash, &words, &mut rng_cheap)?;
        }
    }
    Ok(())
}

fn fetch_wordlist() -> anyhow::Result<Vec<String>> {
    let agent: Agent = Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(30)))
        .timeout_connect(Some(Duration::from_secs(10)))
        .build()
        .into();
    let content = agent
        .get(config::WORDLIST_URL)
        .call()
        .context("failed to download wordlist")?
        .body_mut()
        .read_to_string()
        .context("failed to parse wordlist to string")?;
    let words: Vec<String> = content
        .lines()
        .map(str::trim)
        .filter(|word| word.len() >= config::MIN_WORD_SIZE && word.len() <= config::MAX_WORD_SIZE)
        .map(str::to_string)
        .collect();
    if words.len() < KEY_WORD_COUNT {
        bail!("wordlist too small to sample keys");
    }
    Ok(words)
}

fn group_hash(group: u8) -> String {
    let mut source = [0u8; 65];
    source[..64].copy_from_slice(config::SECRET);
    source[64] = group;
    encode(Sha256::digest(&source))
}

fn docx_text(file_name: &str) -> anyhow::Result<String> {
    let docx = DocxFile::from_file(file_name).context("failed to get DOCX file")?;
    docx.parse()
        .map(|content| content.document.body.text())
        .context("failed to parse DOCX body")
}

fn verify_docx(file_name: &str, hash: &str) -> anyhow::Result<()> {
    println!("File '{file_name}' already exists. Checking file...");
    let file_text = docx_text(file_name)?;
    let file_words: Vec<&str> = file_text.split_whitespace().collect();

    let Some(random_words) = file_words.get(0..KEY_WORD_COUNT) else {
        println!("❌ File {file_name} does not match {hash} (Unable to parse random word key)");
        return Ok(());
    };
    let Some(hash_words) = file_words.get(KEY_WORD_COUNT..) else {
        println!("❌ File {file_name} does not match {hash} (Unable to parse encoding words)");
        return Ok(());
    };
    if hash_words.len() != HASH_HEX_LEN {
        println!(
            "❌ File {file_name} does not match {hash} (expected {HASH_HEX_LEN} encoding words, found {})",
            hash_words.len()
        );
        return Ok(());
    }

    let mut word_hash = String::with_capacity(hash.len());
    for hash_word in hash_words {
        let Some(index) = random_words.iter().position(|word| word == hash_word) else {
            println!(
                "❌ File {file_name} does not match {hash} (Unable to decode word: {hash_word})"
            );
            return Ok(());
        };
        let _ = write!(word_hash, "{index:x}");
    }
    if hash == word_hash {
        println!("✅ File {file_name} matches {hash}");
    } else {
        println!("❌ File {file_name} does not match {hash} ({word_hash})");
    }
    Ok(())
}

fn create_docx(
    file_name: &str,
    hash: &str,
    words: &[String],
    rng: &mut SmallRng,
) -> anyhow::Result<()> {
    println!("File '{file_name}' not found. Creating file...");
    let random_words: Vec<&str> = words
        .sample(rng, KEY_WORD_COUNT)
        .map(String::as_str)
        .collect();
    debug_assert_eq!(random_words.len(), KEY_WORD_COUNT);

    let mut file_content = random_words.join(" ");
    for hex_char in hash.chars() {
        let digit = usize::try_from(
            hex_char
                .to_digit(16)
                .with_context(|| format!("failed to parse hex char: {hex_char}"))?,
        )
        .unwrap_or(0);
        let word = random_words
            .get(digit)
            .context("failed to encode in random word")?;
        file_content.push(' ');
        file_content.push_str(word);
    }

    let mut docx = Docx::default();
    docx.document
        .push(Paragraph::default().push_text(file_content));
    docx.write_file(file_name)
        .context("failed to write to file")?;
    Ok(())
}
