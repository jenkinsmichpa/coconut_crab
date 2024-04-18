use slint::{SharedPixelBuffer, Rgba8Pixel, Image, ComponentHandle};
use log::{debug, error};

use coconut_crab_lib::web::validate::validate_code;
use crate::img::get_icon;
use crate::Main;

pub fn set_window_icon(ui: &Main) {
    let icon = match get_icon() {
        Some(icon_file_result) => {
            icon_file_result
        },
        None => {
            error!("Icon not avilable to set window icon");
            return
        }
    };
    let window_icon = icon.into_rgba8();
    let image_buffer = SharedPixelBuffer::<Rgba8Pixel>::clone_from_slice(
        window_icon.as_raw(),
        window_icon.width(),
        window_icon.height(),
    );
    ui.set_window_icon(Image::from_rgba8(image_buffer));
    debug!("Successfully set window icon");
}

pub fn callback_handler_init(ui: &Main) {
    ui.on_enforce_code_field_format(move |new_text| {
        let mut rust_string = new_text.as_str().to_string();
        debug!("Enforcing format on field: {}", rust_string);
        rust_string.truncate(4);
        let alphanumeric_string = rust_string.chars().filter(|c| c.is_ascii_alphanumeric()).collect::<String>();
        debug!("Formatted field: {}", alphanumeric_string);
        alphanumeric_string.into()
    });

    let ui_handle = ui.as_weak();
    ui.on_update_code(move || {
        let ui = ui_handle.unwrap();

        let code = format!("{}-{}-{}-{}",
        ui.get_code_field_1(),
        ui.get_code_field_2(),
        ui.get_code_field_3(),
        ui.get_code_field_4());
        debug!("Validating entered code: {}", code);

        ui.set_code(code.clone().into());

        if validate_code(&code) {
            debug!("Code is valid");
            ui.set_code_valid(true);
        } else {
            debug!("Code is invalid");
            ui.set_code_valid(false);
        }
    });
}