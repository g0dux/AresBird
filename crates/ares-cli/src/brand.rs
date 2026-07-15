//! Brand banner — shown when AresBird opens in interactive mode.

use console::style;

/// Big stylized wordmark + bird glyph for terminal open.
pub fn print_banner(color: bool) {
    let art = r#"
             .
            /'\
           /   \
      .---/~~~~~\---.      ┏━┓┏━┓┏━╸┏━┓┏┓ ╻┏━┓╺┳┓
     (    .     .    )     ┣━┫┣┳┛┣╸ ┗━┓┣┻┓┃┣┳┛ ┃┃
      '--.\_____/.--'      ┻ ┻╹┗╸┗━╸┗━┛┗━┛╹╹┗╸╺┻┛
           \ V /           network interaction
          __| |__          recon · misconfig · talk
"#;
    if color {
        eprintln!("{}", style(art).cyan().bold());
    } else {
        eprintln!("{art}");
    }
}

pub const PRODUCT: &str = "AresBird";
pub const PRODUCT_TAGLINE: &str = "network interaction engine";
