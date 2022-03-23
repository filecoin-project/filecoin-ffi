/* hack for https://github.com/eqrion/cbindgen/issues/659 */
typedef struct {
  FCPResponseStatus status_code;
  fil_Bytes error_msg;
  void value;
} fil_Result;
