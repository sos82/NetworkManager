use bindgen;
use meson;
use std::env;
use std::path::PathBuf;
use varlink_generator;

fn main() {
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    let meson_path = out_path.join("build");
    let build_path_ndhcp4 = meson_path.join("src");
    let build_path_c_siphash = meson_path.join("subprojects/c-siphash/src");

    meson::build("n-dhcp4", meson_path.to_str().unwrap());

    bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header("wrapper.h")
        .clang_arg("-In-dhcp4/src")
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings")
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");

    println!("cargo:rerun-if-changed=wrapper.h");
    println!("cargo:rustc-link-lib=static=ndhcp4-private");
    println!("cargo:rustc-link-lib=static=csiphash-private");
    println!(
        "cargo:rustc-link-search={}",
        build_path_ndhcp4.to_str().unwrap()
    );
    println!(
        "cargo:rustc-link-search={}",
        build_path_c_siphash.to_str().unwrap()
    );

    varlink_generator::cargo_build_tosource("src/com.redhat.dhcp", true);
}
