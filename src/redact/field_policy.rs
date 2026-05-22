#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldAction {
    Scan,
    SkipKnownBinary,
}

#[derive(Debug, Clone, Default)]
pub struct FieldPolicy;

impl FieldPolicy {
    pub fn action_for_path(&self, path: &[String]) -> FieldAction {
        let suffix = path.join(".");
        if suffix.ends_with("inline_data.data")
            || suffix.ends_with("audio.data")
            || suffix.ends_with("file.bytes")
            || suffix.ends_with("image_url")
        {
            return FieldAction::SkipKnownBinary;
        }
        FieldAction::Scan
    }
}
