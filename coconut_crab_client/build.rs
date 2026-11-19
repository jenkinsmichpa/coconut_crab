use std::env;

fn main() {
    println!("cargo:rerun-if-changed=ui/main.slint");
    println!("cargo:rerun-if-changed=assets/img/favicon.ico");
    let config = slint_build::CompilerConfiguration::new().with_edition((1, 19));
    slint_build::compile_with_config("ui/main.slint", config).expect("Failed to get Slint UI file");

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
