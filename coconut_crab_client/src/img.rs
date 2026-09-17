use image::{DynamicImage, ImageReader};
use log::{debug, error, info};
use std::{io::Cursor, path::Path};

use coconut_crab_lib::file::{get_exe_path_dir, write_to_file};

const ICON_FILENAME: &str = "favicon.png";

const MAX_DECODED_IMAGE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_IMAGE_DIMENSION: u32 = 32_768;

use rust_embed::RustEmbed;
#[derive(RustEmbed)]
#[folder = "assets/img"]
#[include = "favicon.png"]
struct AssetImg;

pub fn img_from_bytes(bytes: &[u8]) -> Result<DynamicImage, image::ImageError> {
    let mut reader = ImageReader::new(Cursor::new(bytes));
    let mut limits = image::Limits::no_limits();
    limits.max_alloc = Some(MAX_DECODED_IMAGE_BYTES);
    limits.max_image_width = Some(MAX_IMAGE_DIMENSION);
    limits.max_image_height = Some(MAX_IMAGE_DIMENSION);
    reader.limits(limits);

    let reader = match reader.with_guessed_format() {
        Ok(reader) => reader,
        Err(error) => {
            debug!("Failed to guess image format: {error}");
            return Err(image::ImageError::IoError(error));
        }
    };
    match reader.decode() {
        Ok(image) => {
            debug!("Successfully decoded image");
            Ok(image)
        }
        Err(error) => {
            debug!("Failed to decode image: {error}");
            Err(error)
        }
    }
}

fn save_icon_to_disk(file_path: &Path) -> Result<(), String> {
    let Some(icon_file) = AssetImg::get(ICON_FILENAME) else {
        error!("Icon not available to save to disk");
        return Err("Icon not available".to_string());
    };
    match write_to_file(&icon_file.data, file_path) {
        Ok(()) => {
            info!("Successfully saved icon to disk");
            Ok(())
        }
        Err(error) => {
            error!("Failed to save icon to disk: {error}");
            Err(error.to_string())
        }
    }
}

pub fn set_icon_wallpaper() {
    let Ok(exe_dir) = get_exe_path_dir() else {
        error!("Cannot determine executable directory, skipping wallpaper");
        return;
    };
    let wallpaper_path = exe_dir.join(ICON_FILENAME);
    if save_icon_to_disk(&wallpaper_path).is_err() {
        return;
    }
    let path_str = wallpaper_path.to_string_lossy();
    match wallpaper::set_from_path(&path_str) {
        Ok(()) => {
            info!("Successfully set wallpaper to icon");
        }
        Err(error) => {
            error!("Failed to set wallpaper to icon: {error}");
            return;
        }
    }
    match wallpaper::set_mode(wallpaper::Mode::Tile) {
        Ok(()) => {
            info!("Successfully set wallpaper mode");
        }
        Err(error) => {
            error!("Failed to set wallpaper mode: {error}");
        }
    }
}
