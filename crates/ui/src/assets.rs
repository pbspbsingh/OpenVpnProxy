use std::sync::LazyLock;

use include_dir::{Dir, include_dir};

static ASSETS: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/assets");

// Compose trusted, embedded view fragments once. No runtime disk reads or frontend build.
static INDEX: LazyLock<String> = LazyLock::new(|| {
    let mut html = ASSETS
        .get_file("index.html")
        .expect("embedded dashboard shell")
        .contents_utf8()
        .expect("UTF-8 dashboard shell")
        .to_owned();
    for view in ASSETS.get_dir("views").expect("dashboard views").files() {
        let name = view.path().file_stem().unwrap().to_str().unwrap();
        html = html.replace(
            &format!("{{{{{name}}}}}"),
            view.contents_utf8().expect("UTF-8 dashboard view"),
        );
    }
    html
});

pub(crate) fn index() -> &'static str {
    &INDEX
}

pub(crate) fn get(path: &str) -> Option<(&'static str, &'static [u8])> {
    let file = ASSETS.get_file(path)?;
    let content_type = match file.path().extension().and_then(|ext| ext.to_str()) {
        Some("js") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("html") => "text/html; charset=utf-8",
        _ => "text/plain; charset=utf-8",
    };
    Some((content_type, file.contents()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_contains_all_views() {
        let html = index();
        assert!(!html.contains("{{"), "unresolved view fragment");
        for name in ["overview", "hosts", "routing", "profile", "logs"] {
            assert!(html.contains(&format!("id=\"{name}\"")));
        }
        let script = std::str::from_utf8(get("app.js").unwrap().1).unwrap();
        assert!(script.contains("https://cdn.jsdelivr.net/npm/alpinejs@"));
        assert!(script.contains("https://cdn.jsdelivr.net/npm/chart.js@"));
    }

    #[test]
    fn directory_embedding_includes_nested_assets_and_rejects_unknown_paths() {
        assert_eq!(
            get("components/hosts.js").unwrap().0,
            "text/javascript; charset=utf-8"
        );
        assert_eq!(get("style.css").unwrap().0, "text/css; charset=utf-8");
        assert_eq!(get("favicon.svg").unwrap().0, "image/svg+xml");
        assert!(get("missing.js").is_none());
        assert!(get("../Cargo.toml").is_none());
    }
}
