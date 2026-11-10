use std::path::{Path, PathBuf};
use std::process::Command;

use eframe::egui;
use egui::{
    Align, Color32, CornerRadius, FontId, Frame, Layout, Margin, RichText, Stroke, TextEdit,
    TextStyle,
};

use pfx_pem_converter::{
    ConversionReport, ConvertError, PemToPfxOptions, PfxToPemOptions, default_pfx_path,
    pem_file_plan, pem_to_pfx, pfx_to_pem,
};

const ACCENT: Color32 = Color32::from_rgb(13, 148, 136);
const SUCCESS: Color32 = Color32::from_rgb(22, 163, 74);
const ERROR: Color32 = Color32::from_rgb(220, 38, 38);
const WARNING: Color32 = Color32::from_rgb(217, 119, 6);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tab {
    PfxToPem,
    PemToPfx,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OutcomeKind {
    Success,
    Error,
}

struct Outcome {
    kind: OutcomeKind,
    title: String,
    message: String,
    files: Vec<PathBuf>,
    warnings: Vec<String>,
    details: Option<String>,
    output_dir: Option<PathBuf>,
}

impl Outcome {
    fn success(report: ConversionReport, message: String) -> Self {
        Self {
            kind: OutcomeKind::Success,
            title: "Done".to_owned(),
            message,
            files: report.outputs,
            warnings: report.warnings,
            details: None,
            output_dir: Some(report.output_dir),
        }
    }

    fn error(
        title: impl Into<String>,
        message: impl Into<String>,
        details: Option<String>,
    ) -> Self {
        Self {
            kind: OutcomeKind::Error,
            title: title.into(),
            message: message.into(),
            files: Vec::new(),
            warnings: Vec::new(),
            details,
            output_dir: None,
        }
    }

    fn from_error(error: ConvertError) -> Self {
        Self::error("Conversion failed", error.to_string(), error.detail())
    }
}

pub struct App {
    tab: Tab,
    pfx_path: String,
    pfx_password: String,
    show_pfx_password: bool,
    pem_output_dir: String,

    key_path: String,
    cert_path: String,
    chain_path: String,
    export_password: String,
    export_password_confirm: String,
    show_export_password: bool,
    pfx_output_path: String,

    outcome: Option<Outcome>,
    scroll_to_outcome: bool,
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        install_fonts(&cc.egui_ctx);

        for theme in [egui::Theme::Dark, egui::Theme::Light] {
            let mut style = (*cc.egui_ctx.style_of(theme)).clone();
            style.spacing.item_spacing = egui::vec2(8.0, 8.0);
            style.spacing.button_padding = egui::vec2(12.0, 6.0);
            style.interaction.selectable_labels = false;

            // The defaults are too small on high-DPI displays. Bump every
            // text role so the whole interface stays consistently readable.
            style
                .text_styles
                .insert(TextStyle::Body, FontId::proportional(20.0));
            style
                .text_styles
                .insert(TextStyle::Button, FontId::proportional(20.0));
            style
                .text_styles
                .insert(TextStyle::Small, FontId::proportional(17.0));
            style
                .text_styles
                .insert(TextStyle::Monospace, FontId::monospace(18.0));
            style
                .text_styles
                .insert(TextStyle::Heading, FontId::proportional(32.0));
            style.visuals.widgets.inactive.corner_radius = CornerRadius::same(6);
            style.visuals.widgets.hovered.corner_radius = CornerRadius::same(6);
            style.visuals.widgets.active.corner_radius = CornerRadius::same(6);
            cc.egui_ctx.set_style_of(theme, style);
        }

        Self {
            tab: Tab::PfxToPem,
            pfx_path: String::new(),
            pfx_password: String::new(),
            show_pfx_password: false,
            pem_output_dir: String::new(),
            key_path: String::new(),
            cert_path: String::new(),
            chain_path: String::new(),
            export_password: String::new(),
            export_password_confirm: String::new(),
            show_export_password: false,
            pfx_output_path: String::new(),
            outcome: None,
            scroll_to_outcome: false,
        }
    }

    fn handle_dropped_files(&mut self, paths: Vec<PathBuf>) {
        if paths.is_empty() {
            return;
        }

        let mut pfx: Option<PathBuf> = None;
        let mut key: Option<PathBuf> = None;
        let mut cert: Option<PathBuf> = None;
        let mut chain: Option<PathBuf> = None;

        for path in paths {
            match classify_file(&path) {
                Some(FileRole::Pfx) => pfx = pfx.or(Some(path)),
                Some(FileRole::Key) => key = key.or(Some(path)),
                Some(FileRole::Cert) => cert = cert.or(Some(path)),
                Some(FileRole::Chain) => chain = chain.or(Some(path)),
                None => {}
            }
        }

        if self.tab == Tab::PfxToPem {
            if let Some(path) = pfx {
                self.pfx_path = path.display().to_string();
                self.outcome = None;
            } else if key.is_some() || cert.is_some() || chain.is_some() {
                self.tab = Tab::PemToPfx;
                self.fill_pem_paths(key, cert, chain);
            }
        } else if let Some(path) = pfx {
            self.tab = Tab::PfxToPem;
            self.pfx_path = path.display().to_string();
            self.outcome = None;
        } else {
            self.fill_pem_paths(key, cert, chain);
        }
    }

    fn fill_pem_paths(
        &mut self,
        key: Option<PathBuf>,
        cert: Option<PathBuf>,
        chain: Option<PathBuf>,
    ) {
        if let Some(path) = key {
            self.key_path = path.display().to_string();
        }
        if let Some(path) = cert {
            self.cert_path = path.display().to_string();
        }
        if let Some(path) = chain {
            self.chain_path = path.display().to_string();
        }
        self.outcome = None;
    }

    fn convert(&mut self) {
        self.scroll_to_outcome = true;
        match self.tab {
            Tab::PfxToPem => self.convert_pfx_to_pem(),
            Tab::PemToPfx => self.convert_pem_to_pfx(),
        }
    }

    fn convert_pfx_to_pem(&mut self) {
        if self.pfx_path.trim().is_empty() {
            self.outcome = Some(Outcome::error(
                "Missing input",
                "Select a PFX or P12 file first.",
                None,
            ));
            return;
        }

        let output_dir = non_empty_path(&self.pem_output_dir);
        let options = PfxToPemOptions {
            input: PathBuf::from(self.pfx_path.trim()),
            password: self.pfx_password.clone(),
            output_dir,
        };

        match pfx_to_pem(&options) {
            Ok(report) => {
                let mut extracted = Vec::new();
                if report.certificate_count > 0 {
                    extracted.push(format!(
                        "{} certificate{}",
                        report.certificate_count,
                        plural(report.certificate_count)
                    ));
                }
                if let Some(kind) = &report.key_type {
                    extracted.push(format!("a private key ({kind})"));
                }

                let message = if extracted.is_empty() {
                    "No output files were created.".to_owned()
                } else {
                    format!(
                        "Extracted {}. Wrote {} file{}.",
                        extracted.join(" and "),
                        report.outputs.len(),
                        plural(report.outputs.len())
                    )
                };
                self.outcome = Some(Outcome::success(report, message));
            }
            Err(error) => self.outcome = Some(Outcome::from_error(error)),
        }
    }

    fn convert_pem_to_pfx(&mut self) {
        if self.key_path.trim().is_empty() || self.cert_path.trim().is_empty() {
            self.outcome = Some(Outcome::error(
                "Missing input",
                "Select both the private key and the certificate.",
                None,
            ));
            return;
        }

        if self.export_password != self.export_password_confirm {
            self.outcome = Some(Outcome::error(
                "Passwords do not match",
                "Type the same password in both password fields.",
                None,
            ));
            return;
        }

        let options = PemToPfxOptions {
            key: PathBuf::from(self.key_path.trim()),
            cert: PathBuf::from(self.cert_path.trim()),
            chain: non_empty_path(&self.chain_path),
            password: self.export_password.clone(),
            output: non_empty_path(&self.pfx_output_path),
        };

        match pem_to_pfx(&options) {
            Ok(report) => {
                let message = format!(
                    "Created a PFX with {} certificate{}.",
                    report.certificate_count,
                    plural(report.certificate_count)
                );
                self.outcome = Some(Outcome::success(report, message));
            }
            Err(error) => self.outcome = Some(Outcome::from_error(error)),
        }
    }

    fn show_pfx_to_pem(&mut self, ui: &mut egui::Ui) {
        let mut changed = false;

        let pfx_start = last_directory(&self.pfx_path);
        changed |= path_row(
            ui,
            "PFX / P12 file",
            "/path/to/certificate.pfx",
            &mut self.pfx_path,
            "Browse…",
            || pick_file("Select a PFX or P12 file", &["pfx", "p12"], pfx_start),
        );

        changed |= password_row(
            ui,
            "Password",
            &mut self.pfx_password,
            &mut self.show_pfx_password,
        );

        let folder_start = last_directory(&self.pfx_path);
        changed |= path_row(
            ui,
            "Output folder (optional)",
            "Same folder as the PFX file",
            &mut self.pem_output_dir,
            "Browse…",
            || pick_folder("Select an output folder", folder_start),
        );

        if let Some(default_dir) = default_pem_output_dir(&self.pfx_path) {
            ui.label(
                RichText::new(format!("Defaults to {}", default_dir.display()))
                    .small()
                    .color(ui.visuals().weak_text_color()),
            );
        }

        ui.add_space(4.0);

        let button = egui::Button::new(
            RichText::new("Convert to PEM")
                .strong()
                .color(Color32::WHITE),
        )
        .fill(ACCENT)
        .corner_radius(CornerRadius::same(8))
        .min_size(egui::vec2(ui.available_width(), 48.0));
        if ui.add(button).clicked() {
            self.convert();
            changed = false;
        }

        ui.label(
            RichText::new(
                "The private key is exported unencrypted. On macOS and Linux the files are created with 0600 permissions.",
            )
            .small()
            .color(ui.visuals().weak_text_color()),
        );

        if changed {
            self.outcome = None;
        }
    }

    fn show_pem_to_pfx(&mut self, ui: &mut egui::Ui) {
        let mut changed = false;

        ui.label(
            RichText::new("The private key must be unencrypted PEM (PKCS#8, PKCS#1 or SEC1).")
                .small()
                .color(ui.visuals().weak_text_color()),
        );

        changed |= path_row(
            ui,
            "Private key (PEM)",
            "/path/to/private-key.pem",
            &mut self.key_path,
            "Browse…",
            || pick_file("Select the private key", &["pem", "key"], None),
        );

        changed |= path_row(
            ui,
            "Certificate (PEM or DER)",
            "/path/to/certificate.pem",
            &mut self.cert_path,
            "Browse…",
            || pick_file("Select the certificate", &["pem", "crt", "cer"], None),
        );

        changed |= path_row(
            ui,
            "Certificate chain (optional)",
            "/path/to/chain.pem",
            &mut self.chain_path,
            "Browse…",
            || pick_file("Select the certificate chain", &["pem", "crt", "cer"], None),
        );

        changed |= password_row(
            ui,
            "PFX password",
            &mut self.export_password,
            &mut self.show_export_password,
        );

        changed |= password_row(
            ui,
            "Confirm password",
            &mut self.export_password_confirm,
            &mut self.show_export_password,
        );

        let save_name = default_pfx_name(&self.cert_path);
        let save_start = last_directory(&self.cert_path);
        changed |= path_row(
            ui,
            "Output PFX (optional)",
            "Same folder as the certificate",
            &mut self.pfx_output_path,
            "Save as…",
            || pick_save("Save the PFX file", &save_name, save_start),
        );

        if !self.cert_path.trim().is_empty() {
            let suggested = default_pfx_path(Path::new(self.cert_path.trim()));
            ui.label(
                RichText::new(format!("Defaults to {}", suggested.display()))
                    .small()
                    .color(ui.visuals().weak_text_color()),
            );
        }

        ui.add_space(4.0);

        let button = egui::Button::new(RichText::new("Create PFX").strong().color(Color32::WHITE))
            .fill(ACCENT)
            .corner_radius(CornerRadius::same(8))
            .min_size(egui::vec2(ui.available_width(), 48.0));
        if ui.add(button).clicked() {
            self.convert();
            changed = false;
        }

        ui.label(
            RichText::new(
                "The PFX uses 3DES/SHA-1 encryption so it imports on Windows and older Java keystores.",
            )
            .small()
            .color(ui.visuals().weak_text_color()),
        );

        if changed {
            self.outcome = None;
        }
    }

    fn show_outcome(&mut self, ui: &mut egui::Ui) -> Option<egui::Response> {
        let outcome = self.outcome.as_ref()?;

        let color = match outcome.kind {
            OutcomeKind::Success => SUCCESS,
            OutcomeKind::Error => ERROR,
        };

        let frame = Frame::new()
            .fill(Color32::from_rgba_unmultiplied(
                color.r(),
                color.g(),
                color.b(),
                if ui.visuals().dark_mode { 28 } else { 16 },
            ))
            .stroke(Stroke::new(
                1.0,
                Color32::from_rgba_unmultiplied(color.r(), color.g(), color.b(), 140),
            ))
            .corner_radius(CornerRadius::same(10))
            .inner_margin(Margin::same(14));

        let response = frame.show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(RichText::new("●").color(color).size(17.0));
                ui.label(RichText::new(&outcome.title).strong().size(21.0));
            });

            ui.label(&outcome.message);

            if !outcome.warnings.is_empty() {
                ui.add_space(4.0);
                for warning in &outcome.warnings {
                    ui.label(
                        RichText::new(format!("Note: {warning}"))
                            .small()
                            .color(WARNING),
                    );
                }
            }

            if !outcome.files.is_empty() {
                ui.add_space(6.0);
                ui.label(
                    RichText::new("Files")
                        .small()
                        .strong()
                        .color(ui.visuals().weak_text_color()),
                );
                for file in &outcome.files {
                    ui.add(
                        egui::Label::new(
                            RichText::new(file.display().to_string())
                                .monospace()
                                .small(),
                        )
                        .wrap(),
                    );
                }

                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    if let Some(dir) = &outcome.output_dir
                        && dir.is_dir()
                        && ui.button("Open folder").clicked()
                    {
                        open_folder(dir);
                    }

                    if ui.button("Copy paths").clicked() {
                        let paths = outcome
                            .files
                            .iter()
                            .map(|path| path.display().to_string())
                            .collect::<Vec<_>>()
                            .join("\n");
                        ui.ctx().copy_text(paths);
                    }
                });
            }

            if let Some(details) = &outcome.details {
                ui.add_space(2.0);
                egui::CollapsingHeader::new("Technical details").show(ui, |ui| {
                    ui.add(
                        egui::Label::new(RichText::new(details).monospace().small())
                            .wrap()
                            .selectable(true),
                    );
                });
            }
        });

        Some(response.response)
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let dropped = ui.ctx().input(|input| {
            input
                .raw
                .dropped_files
                .iter()
                .map(|file| file.path().to_path_buf())
                .collect::<Vec<_>>()
        });
        self.handle_dropped_files(dropped);

        egui::CentralPanel::default().show(ui, |ui| {
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    ui.add_space(6.0);

                    ui.horizontal(|ui| {
                        ui.label(RichText::new("PFX ↔ PEM").size(36.0).strong());
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            ui.label(
                                RichText::new(format!("v{}", env!("CARGO_PKG_VERSION")))
                                    .small()
                                    .color(ui.visuals().weak_text_color()),
                            );
                        });
                    });
                    ui.label(
                        RichText::new(
                            "Convert PKCS#12 bundles to PEM and back. Everything stays on this computer.",
                        )
                        .color(ui.visuals().weak_text_color()),
                    );

                    ui.add_space(8.0);

                    ui.horizontal(|ui| {
                        if ui
                            .selectable_label(
                                self.tab == Tab::PfxToPem,
                                RichText::new("PFX → PEM").size(21.0).strong(),
                            )
                            .clicked()
                        {
                            self.tab = Tab::PfxToPem;
                            self.outcome = None;
                        }
                        if ui
                            .selectable_label(
                                self.tab == Tab::PemToPfx,
                                RichText::new("PEM → PFX").size(21.0).strong(),
                            )
                            .clicked()
                        {
                            self.tab = Tab::PemToPfx;
                            self.outcome = None;
                        }
                    });

                    ui.add_space(6.0);

                    let card = Frame::new()
                        .fill(ui.visuals().faint_bg_color)
                        .stroke(ui.visuals().widgets.noninteractive.bg_stroke)
                        .corner_radius(CornerRadius::same(12))
                        .inner_margin(Margin::same(18));

                    card.show(ui, |ui| match self.tab {
                        Tab::PfxToPem => self.show_pfx_to_pem(ui),
                        Tab::PemToPfx => self.show_pem_to_pfx(ui),
                    });

                    ui.add_space(10.0);
                    let outcome_response = self.show_outcome(ui);

                    if self.scroll_to_outcome {
                        if let Some(response) = outcome_response {
                            response.scroll_to_me(Some(Align::TOP));
                        }
                        self.scroll_to_outcome = false;
                    }

                    ui.add_space(12.0);
                    ui.separator();
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new("Works offline · no telemetry")
                                .small()
                                .color(ui.visuals().weak_text_color()),
                        );
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            ui.label(
                                RichText::new(short_openssl_version())
                                    .small()
                                    .color(ui.visuals().weak_text_color()),
                            );
                        });
                    });

                    ui.label(
                        RichText::new("Tip: you can drag files onto the window.")
                            .small()
                            .color(ui.visuals().weak_text_color()),
                    );
                });
        });
    }
}

fn plural(count: usize) -> &'static str {
    if count == 1 { "" } else { "s" }
}

fn install_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    fonts.font_data.insert(
        "dejavu".to_owned(),
        std::sync::Arc::new(egui::FontData::from_static(include_bytes!(
            "../assets/fonts/DejaVuSans.ttf"
        ))),
    );
    // Keep the compact default UI font first, and use DejaVu only for glyphs
    // missing from it (arrows, Cyrillic, and other symbols).
    for family in [egui::FontFamily::Proportional, egui::FontFamily::Monospace] {
        fonts
            .families
            .entry(family)
            .or_default()
            .push("dejavu".to_owned());
    }
    ctx.set_fonts(fonts);
}

fn path_row(
    ui: &mut egui::Ui,
    label: &str,
    hint: &str,
    value: &mut String,
    button_text: &str,
    pick: impl FnOnce() -> Option<PathBuf>,
) -> bool {
    ui.label(RichText::new(label).strong().size(18.0));

    let mut changed = false;
    let response = ui
        .horizontal(|ui| {
            let button_width = 124.0;
            let text_width =
                (ui.available_width() - button_width - ui.spacing().item_spacing.x).max(120.0);
            let response = ui.add_sized(
                [text_width, 38.0],
                TextEdit::singleline(value).hint_text(hint),
            );
            if ui
                .add_sized([button_width, 38.0], egui::Button::new(button_text))
                .clicked()
                && let Some(path) = pick()
            {
                *value = path.display().to_string();
                changed = true;
            }
            response
        })
        .inner;

    changed || response.changed()
}

fn password_row(ui: &mut egui::Ui, label: &str, value: &mut String, show: &mut bool) -> bool {
    ui.label(RichText::new(label).strong().size(18.0));

    let (changed, toggled) = ui
        .horizontal(|ui| {
            let button_width = 88.0;
            let text_width =
                (ui.available_width() - button_width - ui.spacing().item_spacing.x).max(120.0);
            let response = ui.add_sized(
                [text_width, 38.0],
                TextEdit::singleline(value).password(!*show),
            );
            let toggled = ui
                .add_sized(
                    [button_width, 38.0],
                    egui::Button::new(if *show { "Hide" } else { "Show" }),
                )
                .clicked();
            (response.changed(), toggled)
        })
        .inner;

    if toggled {
        *show = !*show;
    }

    changed
}

fn classify_file(path: &Path) -> Option<FileRole> {
    let extension = path
        .extension()
        .map(|ext| ext.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();

    if extension == "pfx" || extension == "p12" {
        return Some(FileRole::Pfx);
    }

    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();

    let text = std::fs::read(path)
        .ok()
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .unwrap_or_default();

    if text.contains("PRIVATE KEY") || name.contains("key") || extension == "key" {
        return Some(FileRole::Key);
    }

    let certificate_count = text.matches("BEGIN CERTIFICATE-----").count();
    if certificate_count == 0 && !text.contains("CERTIFICATE") {
        return None;
    }

    if name.contains("chain")
        || name.contains("intermediate")
        || name.contains("root")
        || name.contains("ca")
        || certificate_count > 1
    {
        return Some(FileRole::Chain);
    }

    Some(FileRole::Cert)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FileRole {
    Pfx,
    Key,
    Cert,
    Chain,
}

fn pick_file(title: &str, extensions: &[&str], start: Option<PathBuf>) -> Option<PathBuf> {
    let mut dialog = rfd::FileDialog::new().set_title(title);
    if let Some(start) = start {
        dialog = dialog.set_directory(start);
    }
    for extension in extensions {
        dialog = dialog.add_filter(extension.to_uppercase(), &[*extension]);
    }
    dialog.add_filter("All files", &["*"]).pick_file()
}

fn pick_folder(title: &str, start: Option<PathBuf>) -> Option<PathBuf> {
    let mut dialog = rfd::FileDialog::new().set_title(title);
    if let Some(start) = start {
        dialog = dialog.set_directory(start);
    }
    dialog.pick_folder()
}

fn pick_save(title: &str, default_name: &str, start: Option<PathBuf>) -> Option<PathBuf> {
    let mut dialog = rfd::FileDialog::new()
        .set_title(title)
        .set_file_name(default_name);
    if let Some(start) = start {
        dialog = dialog.set_directory(start);
    }
    dialog.add_filter("PFX / P12", &["pfx"]).save_file()
}

fn last_directory(path: &str) -> Option<PathBuf> {
    let path = Path::new(path.trim());
    if path.is_dir() {
        return Some(path.to_path_buf());
    }
    path.parent()
        .filter(|parent| parent.is_dir())
        .map(Path::to_path_buf)
}

fn default_pem_output_dir(pfx_path: &str) -> Option<PathBuf> {
    let path = Path::new(pfx_path.trim());
    if path.as_os_str().is_empty() {
        return None;
    }
    Some(
        pem_file_plan(path, None)
            .certificate
            .parent()?
            .to_path_buf(),
    )
}

fn default_pfx_name(cert_path: &str) -> String {
    let path = Path::new(cert_path.trim());
    if path.as_os_str().is_empty() {
        return "certificate.pfx".to_owned();
    }
    default_pfx_path(path)
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "certificate.pfx".to_owned())
}

fn non_empty_path(value: &str) -> Option<PathBuf> {
    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        Some(PathBuf::from(value))
    }
}

fn short_openssl_version() -> String {
    openssl::version::version()
        .split_whitespace()
        .take(2)
        .collect::<Vec<_>>()
        .join(" ")
}

fn open_folder(path: &Path) {
    #[cfg(target_os = "windows")]
    let program = "explorer";
    #[cfg(target_os = "macos")]
    let program = "open";
    #[cfg(all(unix, not(target_os = "macos")))]
    let program = "xdg-open";

    let _ = Command::new(program).arg(path).spawn();
}
