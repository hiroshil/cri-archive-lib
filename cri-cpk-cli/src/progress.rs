use indicatif::{ProgressBar, ProgressStyle};
use cri_archive_lib::cpk::file::CpkFile;

#[derive(Debug)]
pub struct Progress {
    bar: ProgressBar,
}

impl Progress {
    pub fn new(length: u64) -> Self {
        let bar = ProgressBar::new(length);
        bar.set_style(
            ProgressStyle::with_template(
                "[{elapsed_precise}] {bar:40} {pos:>7}/{len:7} ({percent_precise}%) {msg}"
            ).unwrap().progress_chars("##-"),
        );
        Self { bar }
    }

    pub fn set_current_file(&self, file: &CpkFile) {
        let path = if file.directory().is_empty() {
            file.file_name().to_owned()
        } else {
            format!("{}/{}", file.directory(), file.file_name())
        };
        self.bar.set_message(path);
    }

    pub fn read_one(&self) { self.bar.inc(1); }
    pub fn finish(&self) { self.bar.finish_and_clear(); }
}
