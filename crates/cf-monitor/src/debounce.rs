//! Debouncing logic for the file watcher.
//!
//! Many text editors and tools write files by:
//!   1. Creating a temp file
//!   2. Writing content to it
//!   3. Renaming it to the target path
//!
//! This produces a burst of events (CREATE + MODIFY × N + RENAME) for a
//! single logical "save". The debouncer collapses these into a single event
//! by waiting `debounce_ms` after the last event for a given path.
//!
//! We use `notify`'s built-in `RecommendedWatcher` with `notify_debouncer_full`
//! crate for efficient, OS-native debouncing rather than rolling our own.
//! This module contains the event kind mapping logic.

use cf_common::events::FileEventKind;
use notify::EventKind as NotifyKind;
use notify::event::{
    CreateKind, DataChange, ModifyKind, RemoveKind, RenameMode,
};

/// Map a `notify::EventKind` to our `FileEventKind`.
/// Returns `None` for event types we don't care about (Access, Other, etc.).
pub fn map_event_kind(kind: &NotifyKind) -> Option<FileEventKind> {
    match kind {
        NotifyKind::Create(k) => match k {
            CreateKind::File | CreateKind::Any => Some(FileEventKind::Created),
            _ => None,
        },

        NotifyKind::Modify(k) => match k {
            ModifyKind::Data(DataChange::Content)
            | ModifyKind::Data(DataChange::Any)
            | ModifyKind::Data(DataChange::Size)
            | ModifyKind::Any => Some(FileEventKind::Modified),

            ModifyKind::Name(RenameMode::To)
            | ModifyKind::Name(RenameMode::Both) => Some(FileEventKind::Renamed),

            // Metadata-only changes (permissions, timestamps) — skip
            ModifyKind::Metadata(_) => None,

            _ => None,
        },

        NotifyKind::Remove(k) => match k {
            RemoveKind::File | RemoveKind::Any => Some(FileEventKind::Deleted),
            _ => None,
        },

        // Access events, Other events — not actionable
        _ => None,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use notify::EventKind;
    use notify::event::{CreateKind, ModifyKind, DataChange, RemoveKind};

    #[test]
    fn maps_create_file() {
        let kind = map_event_kind(&EventKind::Create(CreateKind::File));
        assert_eq!(kind, Some(FileEventKind::Created));
    }

    #[test]
    fn maps_modify_content() {
        let kind = map_event_kind(&EventKind::Modify(ModifyKind::Data(DataChange::Content)));
        assert_eq!(kind, Some(FileEventKind::Modified));
    }

    #[test]
    fn maps_remove() {
        let kind = map_event_kind(&EventKind::Remove(RemoveKind::File));
        assert_eq!(kind, Some(FileEventKind::Deleted));
    }

    #[test]
    fn skips_access_events() {
        let kind = map_event_kind(&EventKind::Access(notify::event::AccessKind::Any));
        assert_eq!(kind, None);
    }
}
