use std::env;

fn main() {
    println!("cargo:rerun-if-changed=ui/main.slint");
    println!("cargo:rerun-if-changed=assets/img/favicon.ico");
    slint_build::compile("ui/main.slint").expect("Failed to get Slint UI file");

    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        embed_manifest::embed_manifest(embed_manifest::new_manifest("CoconutCrab.Client"))
            .expect("unable to embed Windows manifest");

        let mut res = winresource::WindowsResource::new();
        res.set_language(0x0409); // English (US)
        res.set_icon("assets/img/favicon.ico");
        res.compile()
            .expect("Failed to build Windows resource file");
    }
}
