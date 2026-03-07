use std::fmt;

#[derive(Debug)]
pub enum AppError {
    Config(String),
    DomainValidation(String),
    Dns(String),
    Acme(String),
    Output(String),
    Interrupted,
    Timeout(String),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppError::Config(msg) => write!(f, "configuration error: {}", msg),
            AppError::DomainValidation(msg) => write!(f, "domain validation error: {}", msg),
            AppError::Dns(msg) => write!(f, "DNS error: {}", msg),
            AppError::Acme(msg) => write!(f, "ACME error: {}", msg),
            AppError::Output(msg) => write!(f, "output error: {}", msg),
            AppError::Interrupted => write!(f, "interrupted by signal"),
            AppError::Timeout(msg) => write!(f, "timeout: {}", msg),
        }
    }
}

impl std::error::Error for AppError {}

/// Returns the stable exit code for the given error category.
pub fn exit_code(error: &AppError) -> i32 {
    match error {
        AppError::Config(_) | AppError::DomainValidation(_) => 1,
        AppError::Dns(_) => 2,
        AppError::Acme(_) => 3,
        AppError::Output(_) => 4,
        AppError::Interrupted => 130,
        AppError::Timeout(_) => 5,
    }
}
