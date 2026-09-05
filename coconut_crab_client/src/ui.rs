use log::debug;
use slint::ComponentHandle;

use crate::Main;
use coconut_crab_lib::web::validate::{validate_code, validate_code_segment};

pub fn callback_handler_init(ui: &Main) {
    ui.on_enforce_code_segment_format(move |new_text| {
        let text = new_text.as_str();
        let alphanumeric_string: String = text
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .take(4)
            .collect();
        debug!("Formatted field: {alphanumeric_string}");
        alphanumeric_string.into()
    });

    ui.on_check_code_segment_format(move |new_text| validate_code_segment(new_text.as_str()));

    let ui_handle = ui.as_weak();
    ui.on_check_code(move || {
        let Some(ui) = ui_handle.upgrade() else {
            return;
        };

        if ui.get_code_segment_1_valid()
            && ui.get_code_segment_2_valid()
            && ui.get_code_segment_3_valid()
            && ui.get_code_segment_4_valid()
        {
            debug!("All code segments are valid");
            let code = format!(
                "{}-{}-{}-{}",
                ui.get_code_segment_1(),
                ui.get_code_segment_2(),
                ui.get_code_segment_3(),
                ui.get_code_segment_4()
            );
            debug!("Validating combined code: {code}");
            let valid = validate_code(&code);
            ui.set_code(code.into());

            if valid {
                debug!("Code is valid");
                ui.set_code_valid(true);
            } else {
                debug!("Code is invalid");
                ui.set_code_valid(false);
            }
        } else {
            debug!("One or more code segment are invalid");
            ui.set_code_valid(false);
        }
    });
}
