fn main() {
    slint_build::compile("ui/main.slint").expect("Failed to get Slint UI file");

    #[cfg(windows)]
    windows_resource::create_windows_resource();
}

#[cfg(windows)]
mod windows_resource {
    extern crate winapi;
    extern crate winres;

    pub fn create_windows_resource() {
        let mut res = winres::WindowsResource::new();
        res.set_language(winapi::um::winnt::MAKELANGID(
            winapi::um::winnt::LANG_ENGLISH,
            winapi::um::winnt::SUBLANG_ENGLISH_US,
        ));
        res.set_icon("assets/img/favicon.ico");
        res.compile()
            .expect("Failed to build Windows resource file");
    }
}
