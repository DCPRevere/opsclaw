//! Mobile entry point for OpsClaw Desktop (iOS/Android).

#[tauri::mobile_entry_point]
fn main() {
    opsclaw_desktop::run();
}
