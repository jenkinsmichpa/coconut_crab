/// Group numbers to create and validate files for \[required\]
pub(crate) const GROUPS: [u8; 10] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

/// URL of wordlist \[required\]
pub(crate) const WORDLIST_URL: &str =
    "https://raw.githubusercontent.com/dwyl/english-words/master/words_alpha.txt";

/// Minimum size of random words \[required\]
pub(crate) const MIN_WORD_SIZE: usize = 4;

/// Maximum size of random words \[required\]
pub(crate) const MAX_WORD_SIZE: usize = 8;

/// Secret to validate word hash \[required\]
pub(crate) const SECRET: &[u8; 64] =
    b"3X9csL9kemmWkJEKGV46NytNFh3w9QSTHcuazXfzfPuasvqeLXjyutQQ6DKTxqs9";
