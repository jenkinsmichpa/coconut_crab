use coconut_crab_lib::file::get_exe_path_dir;
use image::{DynamicImage, ImageReader};
use log::{debug, error, info};
use std::{io::Cursor, path::PathBuf};

const ICON_FILENAME: &str = "favicon.ico";
const ICON_WALLPAPER_FILENAME: &str = "wallpaper.png";

use rust_embed::RustEmbed;
#[derive(RustEmbed)]
#[folder = "assets/img"]
struct AssetImg;

pub fn get_icon() -> Option<DynamicImage> {
    let Some(icon_file) = AssetImg::get(ICON_FILENAME) else {
        error!("Failed to get icon file");
        return None;
    };
    debug!("Successfully got icon file");
    img_from_bytes(&icon_file.data).map_or_else(
        |()| {
            error!("Failed to get decoded icon");
            None
        },
        |image| {
            debug!("Successfully got decoded icon");
            Some(image)
        },
    )
}

pub fn img_from_bytes(bytes: &[u8]) -> Result<DynamicImage, ()> {
    match ImageReader::new(Cursor::new(bytes)).with_guessed_format() {
        Ok(reader) => match reader.decode() {
            Ok(image) => {
                debug!("Successfully decoded image");
                Ok(image)
            }
            Err(error) => {
                error!("Failed to decode image: {error}");
                Err(())
            }
        },
        Err(reader) => {
            error!("Failed to read image: {reader}");
            Err(())
        }
    }
}

fn save_icon_to_disk(file_path: &PathBuf) {
    let Some(icon_file) = get_icon() else {
        error!("Icon not available to save to disk");
        return;
    };
    let icon = icon_file;
    match icon.save(file_path) {
        Ok(()) => {
            info!("Successfully saved icon to disk");
        }
        Err(error) => {
            error!("Failed to save icon to disk: {error}");
        }
    }
}

pub fn set_icon_wallpaper() {
    let wallpaper_path = get_exe_path_dir().join(ICON_WALLPAPER_FILENAME);
    save_icon_to_disk(&wallpaper_path);
    match wallpaper::set_mode(wallpaper::Mode::Tile) {
        Ok(()) => {
            info!("Successfully set wallpaper mode");
        }
        Err(error) => {
            error!("Failed to set wallpaper mode: {error}");
        }
    }
    match wallpaper::set_from_path(&wallpaper_path.to_string_lossy()) {
        Ok(()) => {
            info!("Successfully set wallpaper to icon");
        }
        Err(error) => {
            error!("Failed to set wallpaper to icon: {error}");
        }
    }
}
