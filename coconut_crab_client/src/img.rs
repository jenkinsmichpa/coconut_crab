use std::{io::Cursor, path::Path};

use anyhow::anyhow;
use coconut_crab_lib::file::{current_exe_dir, write_to_file};
use image::{DynamicImage, ImageError, ImageReader, Limits};
use tracing::{debug, error, info};

const ICON_FILENAME: &str = "favicon.png";

const MAX_DECODED_IMAGE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_IMAGE_DIMENSION: u32 = 32_768;

use rust_embed::RustEmbed;
#[derive(RustEmbed)]
#[folder = "assets/img"]
#[include = "favicon.png"]
struct AssetImg;

pub(crate) fn img_from_bytes(bytes: &[u8]) -> Result<DynamicImage, ImageError> {
    let mut reader = ImageReader::new(Cursor::new(bytes));
    let mut limits = Limits::no_limits();
    limits.max_alloc = Some(MAX_DECODED_IMAGE_BYTES);
    limits.max_image_width = Some(MAX_IMAGE_DIMENSION);
    limits.max_image_height = Some(MAX_IMAGE_DIMENSION);
    reader.limits(limits);

    let reader = match reader.with_guessed_format() {
        Ok(reader) => reader,
        Err(error) => {
            debug!(error = ?error, "Failed to guess image format");
            return Err(ImageError::IoError(error));
        }
    };
    match reader.decode() {
        Ok(image) => {
            debug!("Successfully decoded image");
            Ok(image)
        }
        Err(error) => {
            debug!(error = ?error, "Failed to decode image");
            Err(error)
        }
    }
}

fn save_icon_to_disk(file_path: &Path) -> anyhow::Result<()> {
    let Some(icon_file) = AssetImg::get(ICON_FILENAME) else {
        return Err(anyhow!("icon not available"));
    };
    write_to_file(&icon_file.data, file_path)?;
    info!("Successfully saved icon to disk");
    Ok(())
}

pub(crate) fn set_icon_wallpaper() {
    let Ok(exe_dir) = current_exe_dir() else {
        error!("Cannot determine executable directory, skipping wallpaper");
        return;
    };
    let wallpaper_path = exe_dir.join(ICON_FILENAME);
    if let Err(error) = save_icon_to_disk(&wallpaper_path) {
        error!(error = ?error, "Failed to save icon to disk");
        return;
    }
    let path_str = wallpaper_path.to_string_lossy();
    match wallpaper::set_from_path(&path_str) {
        Ok(()) => {
            info!("Successfully set wallpaper to icon");
        }
        Err(error) => {
            error!(error = ?error, "Failed to set wallpaper to icon");
            return;
        }
    }
    match wallpaper::set_mode(wallpaper::Mode::Tile) {
        Ok(()) => {
            info!("Successfully set wallpaper mode");
        }
        Err(error) => {
            error!(error = ?error, "Failed to set wallpaper mode");
        }
    }
}
