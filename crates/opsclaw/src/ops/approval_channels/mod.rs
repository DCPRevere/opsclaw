//! Concrete `ApprovalChannel` implementations — one per transport.

pub mod cli;
pub mod slack;
pub mod telegram;

pub use cli::CliApprovalChannel;
pub use slack::SlackApprovalChannel;
pub use telegram::TelegramApprovalChannel;
