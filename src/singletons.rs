use logging_toolkit::make_logger;
use slog::Logger;

lazy_static! {
    pub static ref FCPFFI_LOG: Logger = make_logger("filecoin-proofs-ffi");
}
