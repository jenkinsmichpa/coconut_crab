use image::{ImageReader, DynamicImage};
use std::{
    io::Cursor,
    path::PathBuf
};
use log::{debug, error, info};
use coconut_crab_lib::file::get_exe_path_dir;

const ICON_FILENAME: &str = "favicon.ico";
const ICON_WALLPAPER_FILENAME: &str = "wallpaper.png";

use rust_embed::RustEmbed;
#[derive(RustEmbed)]
#[folder = "assets/img"]
struct AssetImg;

pub fn get_icon() -> Option<DynamicImage> {
    let icon_file = match AssetImg::get(ICON_FILENAME) {
        Some(icon_file_result) => {
            debug!("Successfully got icon file");
            icon_file_result
        },
        None => {
            error!("Failed to get icon file");
            return None
        }
    };
    match img_from_bytes(&icon_file.data) {
        Ok(icon_decode_result) => {
            debug!("Successfully got decoded icon");
            Some(icon_decode_result)
        },
        Err(_) => {
            error!("Failed to get decoded icon");
            None
        }
    }
}

pub fn img_from_bytes(bytes: &[u8]) -> Result<DynamicImage, ()> {
    match ImageReader::new(Cursor::new(bytes)).with_guessed_format() {
        Ok(icon_read_result) => {
            match icon_read_result.decode() {
                Ok(icon_decode_result) => {
                    debug!("Successfully decoded image");
                    Ok(icon_decode_result)
                },
                Err(icon_decode_result) => {
                    error!("Failed to decode image: {}", icon_decode_result);
                    Err(())
                }
            }
        },
        Err(icon_read_result) => {
            error!("Failed to read image: {}", icon_read_result);
            Err(())
        }
    }
}

fn save_icon_to_disk(file_path: &PathBuf) {
    let icon = match get_icon() {
        Some(icon_file_result) => {
            icon_file_result
        },
        None => {
            error!("Icon not avilable to save to disk");
            return
        }
    };
    match icon.save(file_path)
    {
        Ok(_) => {
            info!("Successfully saved icon to disk");
        },
        Err(icon_save_result) => {
            error!("Failed to save icon to disk: {}", icon_save_result);
        }
    }

}

pub fn set_icon_wallpaper() {
    let wallpaper_path = get_exe_path_dir().join(ICON_WALLPAPER_FILENAME);
    save_icon_to_disk(&wallpaper_path);
    match wallpaper::set_mode(wallpaper::Mode::Tile) {
        Ok(_) => {
            info!("Successfully set wallpaper mode");
        },
        Err(wallpaper_mode_result) => {
            error!("Failed to set wallpaper mode: {}", wallpaper_mode_result);
        }
    }
    match wallpaper::set_from_path(&wallpaper_path.to_string_lossy())
    {
        Ok(_) => {
            info!("Successfully set wallpaper to icon");
        },
        Err(wallpaper_set_result) => {
            error!("Failed to set wallpaper to icon: {}", wallpaper_set_result);
        }
    }
}
