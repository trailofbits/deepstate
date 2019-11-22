extern "C" {
    pub static mut DeepState_UsingLibFuzzer: ::std::os::raw::c_int;
}
extern "C" {
    pub static mut DeepState_UsingSymExec: ::std::os::raw::c_int;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct DeepState_Stream {
    _unused: [u8; 0],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct DeepState_VarArgs {
    pub args: va_list,
}

pub type DeepState_LogLevel = u32;

pub const DeepState_LogLevel_DeepState_LogDebug: DeepState_LogLevel = 0;
pub const DeepState_LogLevel_DeepState_LogTrace: DeepState_LogLevel = 1;
pub const DeepState_LogLevel_DeepState_LogInfo: DeepState_LogLevel = 2;
pub const DeepState_LogLevel_DeepState_LogWarning: DeepState_LogLevel = 3;
pub const DeepState_LogLevel_DeepState_LogWarn: DeepState_LogLevel = 3;
pub const DeepState_LogLevel_DeepState_LogError: DeepState_LogLevel = 4;
pub const DeepState_LogLevel_DeepState_LogExternal: DeepState_LogLevel = 5;
pub const DeepState_LogLevel_DeepState_LogFatal: DeepState_LogLevel = 6;
pub const DeepState_LogLevel_DeepState_LogCritical: DeepState_LogLevel = 6;


extern "C" {
    pub fn DeepState_Log(level: DeepState_LogLevel, str: *const ::std::os::raw::c_char);
}
extern "C" {
    pub fn DeepState_LogFormat(
        level: DeepState_LogLevel,
        format: *const ::std::os::raw::c_char,
        ...
    );
}
extern "C" {
    pub fn DeepState_LogVFormat(
        level: DeepState_LogLevel,
        format: *const ::std::os::raw::c_char,
        args: *mut __va_list_tag,
    );
}
pub const DeepState_OptGroup_InputOutputGroup: DeepState_OptGroup = 0;
pub const DeepState_OptGroup_AnalysisGroup: DeepState_OptGroup = 1;
pub const DeepState_OptGroup_ExecutionGroup: DeepState_OptGroup = 2;
pub const DeepState_OptGroup_TestSelectionGroup: DeepState_OptGroup = 3;
pub const DeepState_OptGroup_MiscGroup: DeepState_OptGroup = 4;

pub type DeepState_OptGroup = u32;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct DeepState_Option {
    pub next: *mut DeepState_Option,
    pub name: *const ::std::os::raw::c_char,
    pub alt_name: *const ::std::os::raw::c_char,
    pub group: DeepState_OptGroup,
    pub parse: ::std::option::Option<unsafe extern "C" fn(arg1: *mut DeepState_Option)>,
    pub value: *mut ::std::os::raw::c_void,
    pub has_value: *mut ::std::os::raw::c_int,
    pub docstring: *const ::std::os::raw::c_char,
}

extern "C" {
    pub static mut DeepState_OptionsAreInitialized: ::std::os::raw::c_int;
}
extern "C" {
    pub fn DeepState_InitOptions(argc: ::std::os::raw::c_int, ...);
}
extern "C" {
    pub fn DeepState_PrintAllOptions(prog_name: *const ::std::os::raw::c_char);
}
extern "C" {
    pub fn DeepState_AddOption(option: *mut DeepState_Option);
}
extern "C" {
    pub fn DeepState_ParseStringOption(option: *mut DeepState_Option);
}
extern "C" {
    pub fn DeepState_ParseBoolOption(option: *mut DeepState_Option);
}
extern "C" {
    pub fn DeepState_ParseIntOption(option: *mut DeepState_Option);
}
extern "C" {
    pub fn DeepState_ParseUIntOption(option: *mut DeepState_Option);
}
extern "C" {
    pub fn DeepState_ClearStream(level: DeepState_LogLevel);
}
extern "C" {
    pub fn DeepState_LogStream(level: DeepState_LogLevel);
}
extern "C" {
    pub fn DeepState_StreamCStr(level: DeepState_LogLevel, begin: *const ::std::os::raw::c_char);
}
extern "C" {
    pub fn DeepState_StreamFormat(
        level: DeepState_LogLevel,
        format: *const ::std::os::raw::c_char,
        ...
    );
}
extern "C" {
    pub fn DeepState_StreamVFormat(
        level: DeepState_LogLevel,
        format: *const ::std::os::raw::c_char,
        args: *mut __va_list_tag,
    );
}
extern "C" {
    pub fn DeepState_StreamDouble(level: DeepState_LogLevel, val: f64);
}
extern "C" {
    pub fn DeepState_StreamPointer(level: DeepState_LogLevel, val: *mut ::std::os::raw::c_void);
}
extern "C" {
    pub fn DeepState_StreamUInt64(level: DeepState_LogLevel, val: u64);
}
extern "C" {
    pub fn DeepState_StreamInt64(level: DeepState_LogLevel, val: i64);
}
extern "C" {
    pub fn DeepState_StreamUInt32(level: DeepState_LogLevel, val: u32);
}
extern "C" {
    pub fn DeepState_StreamInt32(level: DeepState_LogLevel, val: i32);
}
extern "C" {
    pub fn DeepState_StreamUInt16(level: DeepState_LogLevel, val: u16);
}
extern "C" {
    pub fn DeepState_StreamInt16(level: DeepState_LogLevel, val: i16);
}
extern "C" {
    pub fn DeepState_StreamUInt8(level: DeepState_LogLevel, val: u8);
}
extern "C" {
    pub fn DeepState_StreamInt8(level: DeepState_LogLevel, val: i8);
}
extern "C" {
    pub fn DeepState_StreamResetFormatting(level: DeepState_LogLevel);
}
extern "C" {
    pub static mut HAS_FLAG_input_test_dir: ::std::os::raw::c_int;
}
extern "C" {
    pub static mut FLAGS_input_test_dir: *const ::std::os::raw::c_char;
}
extern "C" {
    pub static mut HAS_FLAG_input_test_file: ::std::os::raw::c_int;
}
extern "C" {
    pub static mut FLAGS_input_test_file: *const ::std::os::raw::c_char;
}
extern "C" {
    pub static mut HAS_FLAG_input_test_files_dir: ::std::os::raw::c_int;
}
extern "C" {
    pub static mut FLAGS_input_test_files_dir: *const ::std::os::raw::c_char;
}
extern "C" {
    pub static mut HAS_FLAG_input_which_test: ::std::os::raw::c_int;
}
extern "C" {
    pub static mut FLAGS_input_which_test: *const ::std::os::raw::c_char;
}
extern "C" {
    pub static mut HAS_FLAG_output_test_dir: ::std::os::raw::c_int;
}
extern "C" {
    pub static mut FLAGS_output_test_dir: *const ::std::os::raw::c_char;
}
extern "C" {
    pub static mut HAS_FLAG_test_filter: ::std::os::raw::c_int;
}
extern "C" {
    pub static mut FLAGS_test_filter: *const ::std::os::raw::c_char;
}
extern "C" {
    pub static mut HAS_FLAG_take_over: ::std::os::raw::c_int;
}
extern "C" {
    pub static mut FLAGS_take_over: ::std::os::raw::c_int;
}
extern "C" {
    pub static mut HAS_FLAG_abort_on_fail: ::std::os::raw::c_int;
}
extern "C" {
    pub static mut FLAGS_abort_on_fail: ::std::os::raw::c_int;
}
extern "C" {
    pub static mut HAS_FLAG_exit_on_fail: ::std::os::raw::c_int;
}
extern "C" {
    pub static mut FLAGS_exit_on_fail: ::std::os::raw::c_int;
}
extern "C" {
    pub static mut HAS_FLAG_verbose_reads: ::std::os::raw::c_int;
}
extern "C" {
    pub static mut FLAGS_verbose_reads: ::std::os::raw::c_int;
}
extern "C" {
    pub static mut HAS_FLAG_fuzz: ::std::os::raw::c_int;
}
extern "C" {
    pub static mut FLAGS_fuzz: ::std::os::raw::c_int;
}
extern "C" {
    pub static mut HAS_FLAG_fuzz_save_passing: ::std::os::raw::c_int;
}
extern "C" {
    pub static mut FLAGS_fuzz_save_passing: ::std::os::raw::c_int;
}
extern "C" {
    pub static mut HAS_FLAG_fork: ::std::os::raw::c_int;
}
extern "C" {
    pub static mut FLAGS_fork: ::std::os::raw::c_int;
}
extern "C" {
    pub static mut HAS_FLAG_list_tests: ::std::os::raw::c_int;
}
extern "C" {
    pub static mut FLAGS_list_tests: ::std::os::raw::c_int;
}
extern "C" {
    pub static mut HAS_FLAG_boring_only: ::std::os::raw::c_int;
}
extern "C" {
    pub static mut FLAGS_boring_only: ::std::os::raw::c_int;
}
extern "C" {
    pub static mut HAS_FLAG_run_disabled: ::std::os::raw::c_int;
}
extern "C" {
    pub static mut FLAGS_run_disabled: ::std::os::raw::c_int;
}
extern "C" {
    pub static mut HAS_FLAG_min_log_level: ::std::os::raw::c_int;
}
extern "C" {
    pub static mut FLAGS_min_log_level: ::std::os::raw::c_int;
}
extern "C" {
    pub static mut HAS_FLAG_seed: ::std::os::raw::c_int;
}
extern "C" {
    pub static mut FLAGS_seed: ::std::os::raw::c_int;
}
extern "C" {
    pub static mut HAS_FLAG_timeout: ::std::os::raw::c_int;
}
extern "C" {
    pub static mut FLAGS_timeout: ::std::os::raw::c_int;
}
pub const DeepState_InputSize: u32 = 8192;

extern "C" {
    pub static mut DeepState_Input: [u8; DeepState_InputSize];
}
extern "C" {
    pub static mut DeepState_InputIndex: u32;
}
extern "C" {
    pub fn DeepState_Bool() -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn DeepState_Size() -> usize;
}
extern "C" {
    pub fn DeepState_Long() -> ::std::os::raw::c_long;
}
extern "C" {
    pub fn DeepState_Float() -> f32;
}
extern "C" {
    pub fn DeepState_Double() -> f64;
}
extern "C" {
    pub fn DeepState_UInt64() -> u64;
}
extern "C" {
    pub fn DeepState_Int64() -> i64;
}
extern "C" {
    pub fn DeepState_UInt() -> u32;
}
extern "C" {
    pub fn DeepState_Int() -> i32;
}
extern "C" {
    pub fn DeepState_RandInt() -> i32;
}
extern "C" {
    pub fn DeepState_UShort() -> u16;
}
extern "C" {
    pub fn DeepState_Short() -> i16;
}
extern "C" {
    pub fn DeepState_UChar() -> u8;
}
extern "C" {
    pub fn DeepState_Char() -> i8;
}
extern "C" {
    pub fn DeepState_MinUInt(arg1: u32) -> u32;
}
extern "C" {
    pub fn DeepState_MinInt(arg1: i32) -> i32;
}
extern "C" {
    pub fn DeepState_MaxUInt(arg1: u32) -> u32;
}
extern "C" {
    pub fn DeepState_MaxInt(arg1: i32) -> i32;
}
extern "C" {
    pub fn DeepState_CleanUp();
}
extern "C" {
    pub fn DeepState_IsTrue(expr: ::std::os::raw::c_int) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn DeepState_One() -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn DeepState_Zero() -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn DeepState_ZeroSink(arg1: ::std::os::raw::c_int) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn DeepState_SymbolizeData(
        begin: *mut ::std::os::raw::c_void,
        end: *mut ::std::os::raw::c_void,
    );
}
extern "C" {
    pub fn DeepState_SymbolizeDataNoNull(
        begin: *mut ::std::os::raw::c_void,
        end: *mut ::std::os::raw::c_void,
    );
}
extern "C" {
    pub fn DeepState_ConcretizeData(
        begin: *mut ::std::os::raw::c_void,
        end: *mut ::std::os::raw::c_void,
    ) -> *mut ::std::os::raw::c_void;
}
extern "C" {
    pub fn DeepState_AssignCStr_C(
        str: *mut ::std::os::raw::c_char,
        len: usize,
        allowed: *const ::std::os::raw::c_char,
    );
}
extern "C" {
    pub fn DeepState_CStr_C(
        len: usize,
        allowed: *const ::std::os::raw::c_char,
    ) -> *mut ::std::os::raw::c_char;
}
extern "C" {
    pub fn DeepState_SymbolizeCStr_C(
        begin: *mut ::std::os::raw::c_char,
        allowed: *const ::std::os::raw::c_char,
    );
}
extern "C" {
    pub fn DeepState_ConcretizeCStr(
        begin: *const ::std::os::raw::c_char,
    ) -> *const ::std::os::raw::c_char;
}
extern "C" {
    pub fn DeepState_Malloc(num_bytes: usize) -> *mut ::std::os::raw::c_void;
}
extern "C" {
    pub fn _DeepState_Assume(
        expr: ::std::os::raw::c_int,
        expr_str: *const ::std::os::raw::c_char,
        file: *const ::std::os::raw::c_char,
        line: ::std::os::raw::c_uint,
    );
}
pub const DeepState_TestRunResult_DeepState_TestRunPass: DeepState_TestRunResult = 0;
pub const DeepState_TestRunResult_DeepState_TestRunFail: DeepState_TestRunResult = 1;
pub const DeepState_TestRunResult_DeepState_TestRunCrash: DeepState_TestRunResult = 2;
pub const DeepState_TestRunResult_DeepState_TestRunAbandon: DeepState_TestRunResult = 3;
pub type DeepState_TestRunResult = u32;
extern "C" {
    pub fn DeepState_Abandon(reason: *const ::std::os::raw::c_char);
}
extern "C" {
    pub fn DeepState_Crash();
}
extern "C" {
    pub fn DeepState_Fail();
}
extern "C" {
    pub fn DeepState_SoftFail();
}
extern "C" {
    pub fn DeepState_Pass();
}
extern "C" {
    pub fn DeepState_FloatInRange(low: f32, high: f32) -> f32;
}
extern "C" {
    pub fn DeepState_DoubleInRange(low: f64, high: f64) -> f64;
}
extern "C" {
    pub fn DeepState_IsSymbolicUInt(x: u32) -> ::std::os::raw::c_int;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct DeepState_TestInfo {
    pub prev: *mut DeepState_TestInfo,
    pub test_func: ::std::option::Option<unsafe extern "C" fn()>,
    pub test_name: *const ::std::os::raw::c_char,
    pub file_name: *const ::std::os::raw::c_char,
    pub line_number: ::std::os::raw::c_uint,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct DeepState_TestRunInfo {
    pub test: *mut DeepState_TestInfo,
    pub result: DeepState_TestRunResult,
    pub reason: *const ::std::os::raw::c_char,
}

extern "C" {
    pub static mut DeepState_LastTestInfo: *mut DeepState_TestInfo;
}
extern "C" {
    pub static mut DeepState_FirstTestInfo: *mut DeepState_TestInfo;
}
extern "C" {
    pub fn DeepState_TakeOver() -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn DeepState_Setup();
}
extern "C" {
    pub fn DeepState_Teardown();
}
extern "C" {
    pub fn DeepState_BeginDrFuzz(info: *mut DeepState_TestInfo);
}
extern "C" {
    pub fn DeepState_Begin(info: *mut DeepState_TestInfo);
}
extern "C" {
    pub fn DeepState_FirstTest() -> *mut DeepState_TestInfo;
}
extern "C" {
    pub fn DeepState_CatchFail() -> bool;
}
extern "C" {
    pub fn DeepState_CatchAbandoned() -> bool;
}
extern "C" {
    pub fn DeepState_SavePassingTest();
}
extern "C" {
    pub fn DeepState_SaveFailingTest();
}
extern "C" {
    pub fn DeepState_SaveCrashingTest();
}
extern "C" {
    pub static mut DeepState_ReturnToRun: jmp_buf;
}
extern "C" {
    pub fn DeepState_Warn_srand(seed: ::std::os::raw::c_uint);
}
extern "C" {
    pub fn DeepState_FuzzOneTestCase(test: *mut DeepState_TestInfo) -> DeepState_TestRunResult;
}
extern "C" {
    pub fn DeepState_Fuzz() -> ::std::os::raw::c_int;
}
extern "C" {
    pub static mut DeepState_Option_input_test_dir: DeepState_Option;
}
extern "C" {
    pub static mut DeepState_Option_input_test_file: DeepState_Option;
}
extern "C" {
    pub static mut DeepState_Option_input_test_files_dir: DeepState_Option;
}
extern "C" {
    pub static mut DeepState_Option_output_test_dir: DeepState_Option;
}
extern "C" {
    pub static mut DeepState_Option_take_over: DeepState_Option;
}
extern "C" {
    pub static mut DeepState_Option_abort_on_fail: DeepState_Option;
}
extern "C" {
    pub static mut DeepState_Option_exit_on_fail: DeepState_Option;
}
extern "C" {
    pub static mut DeepState_Option_verbose_reads: DeepState_Option;
}
extern "C" {
    pub static mut DeepState_Option_min_log_level: DeepState_Option;
}
extern "C" {
    pub static mut DeepState_Option_timeout: DeepState_Option;
}
extern "C" {
    pub static mut HAS_FLAG_num_workers: ::std::os::raw::c_int;
}
extern "C" {
    pub static mut FLAGS_num_workers: ::std::os::raw::c_uint;
}
extern "C" {
    pub static mut DeepState_Option_num_workers: DeepState_Option;
}
extern "C" {
    pub static mut DeepState_Option_fuzz: DeepState_Option;
}
extern "C" {
    pub static mut DeepState_Option_fuzz_save_passing: DeepState_Option;
}
extern "C" {
    pub static mut DeepState_Option_fork: DeepState_Option;
}
extern "C" {
    pub static mut DeepState_Option_seed: DeepState_Option;
}
extern "C" {
    pub static mut DeepState_Option_input_which_test: DeepState_Option;
}
extern "C" {
    pub static mut DeepState_Option_test_filter: DeepState_Option;
}
extern "C" {
    pub static mut DeepState_Option_list_tests: DeepState_Option;
}
extern "C" {
    pub static mut DeepState_Option_boring_only: DeepState_Option;
}
extern "C" {
    pub static mut DeepState_Option_run_disabled: DeepState_Option;
}
pub const DeepState_LibFuzzerLoud: ::std::os::raw::c_int = 0;
extern "C" {
    pub static mut DeepState_GeneratedStrings: [*mut ::std::os::raw::c_char; 8192usize];
}
pub const DeepState_GeneratedStringsIndex: u32 = 0;
extern "C" {
    pub static mut DeepState_DrFuzzTest: *mut DeepState_TestInfo;
}
extern "C" {
    pub static mut DeepState_CurrentTestRun: *mut DeepState_TestRunInfo;
}
extern "C" {
    pub fn DeepState_AllocCurrentTestRun();
}
extern "C" {
    pub fn DeepState_MemScrub(
        pointer: *mut ::std::os::raw::c_void,
        data_size: usize,
    ) -> *mut ::std::os::raw::c_void;
}
extern "C" {
    pub fn _DeepState_StreamInt(
        level: DeepState_LogLevel,
        format: *const ::std::os::raw::c_char,
        unpack: *const ::std::os::raw::c_char,
        val: *mut u64,
    );
}
extern "C" {
    pub fn _DeepState_StreamFloat(
        level: DeepState_LogLevel,
        format: *const ::std::os::raw::c_char,
        unpack: *const ::std::os::raw::c_char,
        val: *mut f64,
    );
}
extern "C" {
    pub fn _DeepState_StreamString(
        level: DeepState_LogLevel,
        format: *const ::std::os::raw::c_char,
        str: *const ::std::os::raw::c_char,
    );
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct DeepState_IndexEntry {
    pub name: *const ::std::os::raw::c_char,
    pub address: *mut ::std::os::raw::c_void,
}

extern "C" {
    pub static mut DeepState_API: [DeepState_IndexEntry; 24usize];
}
extern "C" {
    pub fn DrMemFuzzFunc(buff: *mut u8, size: usize);
}
extern "C" {
    pub fn DeepState_RunSavedTakeOverCases(env: *mut __jmp_buf_tag, test: *mut DeepState_TestInfo);
}
extern "C" {
    pub fn makeFilename(name: *mut ::std::os::raw::c_char, size: usize);
}
extern "C" {
    pub fn writeInputData(name: *mut ::std::os::raw::c_char, important: ::std::os::raw::c_int);
}
extern "C" {
    pub fn LLVMFuzzerTestOneInput(Data: *const u8, Size: usize) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn FuzzerEntrypoint(data: *const u8, size: usize) -> ::std::os::raw::c_int;
}
