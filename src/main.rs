use ssh_control::app::App;
use ssh_control::config::ConfigStore;
use ssh_control::error::Result;
use ssh_control::terminal::TerminalGuard;

#[tokio::main]
async fn main() -> Result<()> {
    let path = ConfigStore::resolve_default_path()?;
    let store = ConfigStore::new(path);

    let mut terminal = TerminalGuard::init()?;
    let mut app = App::new(store);
    let result = app.run(&mut terminal).await;
    drop(terminal);

    result
}
