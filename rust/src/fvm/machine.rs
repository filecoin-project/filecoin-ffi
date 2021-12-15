use std::ptr;


use drop_struct_macro_derive::DropStructMacro;
// `CodeAndMessage` is the trait implemented by `code_and_message_impl
use ffi_toolkit::{code_and_message_impl, free_c_str, CodeAndMessage, FCPResponseStatus};

use fvm::machine::Machine;
