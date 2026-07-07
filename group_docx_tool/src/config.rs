/// Group numbers to create and validate files for [required]
pub const GROUPS: [u8; 10] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

/// URL of wordlist [required]
pub const WORDLIST_URL: &str =
    "https://raw.githubusercontent.com/dwyl/english-words/master/words_alpha.txt";

/// Minimum size of random words [required]
pub const MIN_WORD_SIZE: usize = 4;

/// Maximum size of random words [required]
pub const MAX_WORD_SIZE: usize = 8;

/// Secret to validate word hash [required]
pub static SECRET: &[u8; 64] = b"3X9csL9kemmWkJEKGV46NytNFh3w9QSTHcuazXfzfPuasvqeLXjyutQQ6DKTxqs9";
