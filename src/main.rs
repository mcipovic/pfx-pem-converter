#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

mod app;
mod selftest;

use eframe::egui;

fn main() -> eframe::Result {
    let arguments: Vec<String> = std::env::args().skip(1).collect();

    if arguments.iter().any(|arg| arg == "--help" || arg == "-h") {
        print_help();
        return Ok(());
    }

    if arguments
        .iter()
        .any(|arg| arg == "--version" || arg == "-V")
    {
        println!("pfx-pem {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    if arguments.iter().any(|arg| arg == "--self-test") {
        return match selftest::run() {
            Ok(()) => {
                println!("self-test: OK");
                Ok(())
            }
            Err(error) => {
                eprintln!("self-test failed: {error}");
                std::process::exit(1);
            }
        };
    }

    run_gui()
}

fn run_gui() -> eframe::Result {
    let icon = eframe::icon_data::from_png_bytes(include_bytes!("../assets/icon-256.png"))
        .unwrap_or_default();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("PFX ↔ PEM")
            .with_inner_size([820.0, 720.0])
            .with_min_inner_size([660.0, 560.0])
            .with_icon(icon),
        renderer: eframe::Renderer::Glow,
        centered: true,
        ..Default::default()
    };

    eframe::run_native(
        "PFX ↔ PEM",
        options,
        Box::new(|cc| Ok(Box::new(app::App::new(cc)))),
    )
}

fn print_help() {
    println!(
        "\
PFX ↔ PEM Converter {}

Usage:
  pfx-pem             Open the graphical application.
  pfx-pem --self-test Run a headless conversion self-test.
  pfx-pem --version   Print the version.
  pfx-pem --help      Show this help.

The application converts between PFX/PKCS#12 and PEM files. It runs fully
offline and uses a bundled copy of OpenSSL.
",
        env!("CARGO_PKG_VERSION")
    );
}
