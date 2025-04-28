use sha2::{ Sha256, Digest };
use hex::encode;
use rand::seq::SliceRandom;
use rand::{ SeedableRng, rngs::SmallRng };
use std::fs;
use docx_rust::{ document::Paragraph, Docx, DocxFile };
use ureq::get;

/*

+---------------------+
| CONFIGURATION START |
+---------------------+

*/

// Configure group numbers to create and validate files for [required]
const GROUPS: [u8; 10] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
// Configure URL of wordlist [required]
const WORDLIST_URL: &str =
    "https://raw.githubusercontent.com/dwyl/english-words/master/words_alpha.txt";
// Configure minimum size of random words [required]
const MIN_WORD_SIZE: usize = 4;
// Configure maximum size of random words [required]
const MAX_WORD_SIZE: usize = 8;
// Configure secret to validate word hash [required]
static SECRET: &[u8; 64] = b"3X9csL9kemmWkJEKGV46NytNFh3w9QSTHcuazXfzfPuasvqeLXjyutQQ6DKTxqs9";

/*

+-------------------+
| CONFIGURATION END |
+-------------------+

*/

fn main() {
    let content = get(WORDLIST_URL)
        .call()
        .expect("Failed to download wordlist")
        .body_mut()
        .read_to_string()
        .expect("Failed to parse wordlist to string");
    let words: Vec<&str> = content
        .lines()
        .map(|x| x.trim())
        .filter(|x| x.len() >= MIN_WORD_SIZE && x.len() <= MAX_WORD_SIZE)
        .collect();
    let mut rng_cheap = SmallRng::from_os_rng();
    let mut hasher = Sha256::new();

    for group in GROUPS {
        let file_name = format!("Group {} Important Document.docx", group);
        let mut source = SECRET.to_vec();
        source.push(group);
        hasher.update(source);
        let hash = encode(hasher.finalize_reset());

        if fs::metadata(&file_name).is_ok() {
            println!("File '{}' already exists. Checking file...", file_name);

            let docx = DocxFile::from_file(&file_name).expect("Failed to get DOCX file");

            let file_content = match docx.parse() {
                Ok(file_content_result) => { file_content_result.document.body.text() }
                Err(file_content_result) => {
                    println!(
                        "❌ File {} does not match {} ({:?})",
                        file_name,
                        hash,
                        file_content_result
                    );
                    continue;
                }
            };

            let words: Vec<&str> = file_content.split_whitespace().collect();
            let random_words = match words.get(0..16) {
                Some(random_words_result) => { random_words_result }
                None => {
                    println!(
                        "❌ File {} does not match {} (Unable to parse random word key)",
                        file_name,
                        hash
                    );
                    continue;
                }
            };

            let hash_words = match words.get(16..) {
                Some(hash_words_result) => { hash_words_result }
                None => {
                    println!(
                        "❌ File {} does not match {} (Unable to parse encoding words)",
                        file_name,
                        hash
                    );
                    continue;
                }
            };

            let mut word_hash = String::new();
            for hash_word in hash_words {
                let index = match random_words.iter().position(|x| x == hash_word) {
                    Some(index_result) => { index_result }
                    None => {
                        println!(
                            "❌ File {} does not match {} (Unable to decode word: {})",
                            file_name,
                            hash,
                            hash_word
                        );
                        continue;
                    }
                };
                word_hash = format!("{}{:x}", word_hash, index);
            }
            if hash == word_hash {
                println!("✅ File {} matches {}", file_name, hash);
            } else {
                println!("❌ File {} does not match {} ({})", file_name, hash, word_hash);
            }
        } else {
            println!("File '{}' not found. Creating file...", file_name);

            let mut indices: Vec<usize> = (0..words.len()).collect();
            indices.shuffle(&mut rng_cheap);
            indices.truncate(16);

            let random_words: Vec<String> = indices
                .iter()
                .map(|&i| &words[i])
                .map(|i| i.to_string())
                .collect();

            let mut file_content = random_words.join(" ");
            for hex_char in hash.chars() {
                let word = random_words
                    .get(
                        u8
                            ::from_str_radix(&hex_char.to_string(), 16)
                            .expect("Failed to parse hex to byte") as usize
                    )
                    .expect("Failed to encode in random word");
                file_content = format!("{} {}", file_content, word);
            }

            let mut docx = Docx::default();
            let paragraph = Paragraph::default().push_text(file_content);
            docx.document.push(paragraph);
            docx.write_file(&file_name).expect("Failed to write to file");
        }
    }
}
