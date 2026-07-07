use docx_rust::{Docx, DocxFile, document::Paragraph};
use hex::encode;
use purecrypto::hash::{Digest, Sha256};
use rand::seq::SliceRandom;
use rand::{SeedableRng, rngs::SmallRng};
use std::fs;
use ureq::get;

mod config;

fn main() {
    let content = get(config::WORDLIST_URL)
        .call()
        .expect("Failed to download wordlist")
        .body_mut()
        .read_to_string()
        .expect("Failed to parse wordlist to string");
    let words: Vec<&str> = content
        .lines()
        .map(str::trim)
        .filter(|x| x.len() >= config::MIN_WORD_SIZE && x.len() <= config::MAX_WORD_SIZE)
        .collect();
    let mut rng_cheap = SmallRng::from_rng(&mut rand::rng());

    for group in config::GROUPS {
        let file_name = format!("Group {group} Important Document.docx");
        let mut source = config::SECRET.to_vec();
        source.push(group);
        let hash = encode(Sha256::digest(&source));

        if fs::metadata(&file_name).is_ok() {
            println!("File '{file_name}' already exists. Checking file...");

            let docx = DocxFile::from_file(&file_name).expect("Failed to get DOCX file");

            let file_content = match docx.parse() {
                Ok(content) => content.document.body.text(),
                Err(error) => {
                    println!("❌ File {file_name} does not match {hash} ({error:?})");
                    continue;
                }
            };

            let words: Vec<&str> = file_content.split_whitespace().collect();
            let Some(random_words) = words.get(0..16) else {
                println!(
                    "❌ File {file_name} does not match {hash} (Unable to parse random word key)"
                );
                continue;
            };

            let Some(hash_words) = words.get(16..) else {
                println!(
                    "❌ File {file_name} does not match {hash} (Unable to parse encoding words)"
                );
                continue;
            };

            let mut word_hash = String::new();
            for hash_word in hash_words {
                let Some(index) = random_words.iter().position(|x| x == hash_word) else {
                    println!(
                        "❌ File {file_name} does not match {hash} (Unable to decode word: {hash_word})"
                    );
                    continue;
                };
                word_hash = format!("{word_hash}{index:x}");
            }
            if hash == word_hash {
                println!("✅ File {file_name} matches {hash}");
            } else {
                println!("❌ File {file_name} does not match {hash} ({word_hash})");
            }
        } else {
            println!("File '{file_name}' not found. Creating file...");

            let mut indices: Vec<usize> = (0..words.len()).collect();
            indices.shuffle(&mut rng_cheap);
            indices.truncate(16);

            let random_words: Vec<String> = indices
                .iter()
                .map(|&i| &words[i])
                .map(std::string::ToString::to_string)
                .collect();

            let mut file_content = random_words.join(" ");
            for hex_char in hash.chars() {
                let word = random_words
                    .get(
                        u8::from_str_radix(&hex_char.to_string(), 16)
                            .expect("Failed to parse hex to byte") as usize,
                    )
                    .expect("Failed to encode in random word");
                file_content = format!("{file_content} {word}");
            }

            let mut docx = Docx::default();
            let paragraph = Paragraph::default().push_text(file_content);
            docx.document.push(paragraph);
            docx.write_file(&file_name)
                .expect("Failed to write to file");
        }
    }
}
