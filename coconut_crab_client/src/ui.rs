use slint::{ SharedPixelBuffer, Rgba8Pixel, Image, ComponentHandle };
use log::{ debug, error };

use coconut_crab_lib::web::validate::{validate_code_segment, validate_code};
use crate::img::get_icon;
use crate::Main;

pub fn set_window_icon(ui: &Main) {
    let icon = match get_icon() {
        Some(icon_file_result) => { icon_file_result }
        None => {
            error!("Icon not avilable to set window icon");
            return;
        }
    };
    let window_icon = icon.into_rgba8();
    let image_buffer = SharedPixelBuffer::<Rgba8Pixel>::clone_from_slice(
        window_icon.as_raw(),
        window_icon.width(),
        window_icon.height()
    );
    ui.set_window_icon(Image::from_rgba8(image_buffer));
    debug!("Successfully set window icon");
}

pub fn callback_handler_init(ui: &Main) {
    ui.on_enforce_code_segment_format(move |new_text| {
        let mut rust_string = new_text.as_str().to_string();
        debug!("Enforcing format on code segment: {}", rust_string);
        rust_string.truncate(4);
        let alphanumeric_string = rust_string
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .collect::<String>();
        debug!("Formatted field: {}", alphanumeric_string);
        alphanumeric_string.into()
    });

    ui.on_check_code_segment_format(move |new_text| {
        let code_segment = new_text.as_str().to_string();
        debug!("Validating code segment field: {}", code_segment);
        validate_code_segment(&code_segment)
    });

    let ui_handle = ui.as_weak();
    ui.on_check_code(move || {
        let ui = ui_handle.unwrap();

        if ui.get_code_segment_1_valid() && ui.get_code_segment_2_valid() && ui.get_code_segment_3_valid() && ui.get_code_segment_4_valid() {
            debug!("All code segments are valid");
            let code = format!(
                "{}-{}-{}-{}",
                ui.get_code_segment_1(),
                ui.get_code_segment_2(),
                ui.get_code_segment_3(),
                ui.get_code_segment_4()
            );
            debug!("Validating combined code: {}", code);
            ui.set_code(code.clone().into());

            if validate_code(&code) {
                debug!("Code is valid");
                ui.set_code_valid(true);
            } else {
                debug!("Code is invalid");
                ui.set_code_valid(false);
            }
        } else {
            debug!("One or more code segment are invalid")
        }
    });
}
