#![feature(once_cell)]
#![feature(naked_functions)]

use ctor::ctor;
use frida_gum::{interceptor::Interceptor, Gum, Module};
use std::{arch::asm, sync::LazyLock};
use tracing::{info, trace};
use tracing_subscriber::prelude::*;

static GUM: LazyLock<Gum> = LazyLock::new(|| unsafe { Gum::obtain() });

/// [Naked function] 6 param version, used by Rawsyscall & Syscall
#[naked]
unsafe extern "C" fn syscall_6(
    syscall: i64,
    param1: i64,
    param2: i64,
    param3: i64,
    param4: i64,
    param5: i64,
    param6: i64,
) -> i64 {
    asm!(
        "mov    rax, rdi",
        "mov    rdi, rsi",
        "mov    rsi, rdx",
        "mov    rdx, rcx",
        "mov    r10, r8",
        "mov    r8, r9",
        "mov    r9, QWORD PTR[rsp]",
        "syscall",
        "ret",
        options(noreturn)
    )
}

/// Syscall & Syscall6 handler - supports upto 6 params, mainly used for
/// accept4 Note: Depending on success/failure Syscall may or may not call this handler
#[no_mangle]
unsafe extern "C" fn c_abi_syscall6_handler(
    syscall: i64,
    param1: i64,
    param2: i64,
    param3: i64,
    param4: i64,
    param5: i64,
    param6: i64,
) -> i64 {
    trace!(
        "c_abfi_syscall6_handler: syscall={} param1={} param2={} param3={} param4={}
        param5={} param6={}",
        syscall,
        param1,
        param2,
        param3,
        param4,
        param5,
        param6
    );

    let syscall_res = syscall_6(syscall, param1, param2, param3, param4, param5, param6);
    trace!("returning {syscall_res:?}");
    return syscall_res;
}

/// [Naked function] 3 param version (Syscall6) for making the syscall, libc's syscall is not
/// used here as it doesn't return the value that go expects (it does translation)
#[naked]
unsafe extern "C" fn syscall_3(syscall: i64, param1: i64, param2: i64, param3: i64) -> i64 {
    asm!(
        "mov    rax, rdi",
        "mov    rdi, rsi",
        "mov    rsi, rdx",
        "mov    rdx, rcx",
        "syscall",
        "ret",
        options(noreturn)
    )
}

#[naked]
unsafe extern "C" fn go_syscall_new_detour() {
    asm!(
        // Save rdi in r10
        "mov r10, rdi",
        // Save r9 in r11
        "mov r11, r9",
        // Save rax in r12
        "mov r12, rax",
        "mov r13, rbx",
        // Switch stack
        // "mov    rdx, rsp", // save stack in rdx
        // "mov    rdi, QWORD PTR fs:[0xfffffff8]", // put g in rdi
        // "cmp    rdi, 0x0", // check if g is null
        // "je     2f", // jump to no g flow
        // "mov    r8, QWORD PTR [rdi+0x30]", //
        // "mov    rsi, QWORD PTR [r8+0x50]",
        // "cmp    rdi,rsi",
        // "je     2f",
        // "mov    rsi, QWORD PTR [r8]",
        // "cmp    rdi, rsi",
        // "je     2f",
        // "call   go_systemstack_switch",
        // "mov    QWORD PTR fs:[0xfffffff8], rsi",
        // "mov    rsp, QWORD PTR [rsi+0x38]",
        // "sub    rsp, 0x40",
        // "and    rsp, 0xfffffffffffffff0",
        // "mov    QWORD PTR [rsp+0x30],rdi",
        // "mov    rdi, QWORD PTR [rdi+0x8]",
        // "sub    rdi, rdx",
        // new attempt at stack
        "mov rax, QWORD PTR fs:[0xfffffff8]",
        "mov rbx, QWORD PTR [rax + 0x30]",
        "cmp rax, QWORD PTR [rbx + 0x50]",
        "jz 35f",
        "mov rdx, QWORD PTR [RBX]",
        "cmp rax, rdx",
        "jz 36f",
        "call go_systemstack_switch",
        "mov QWORD PTR FS:[0xfffffff8], RDX",
        "mov r14, rdx",
        "mov rbx, QWORD PTR [rdx + 0x38]",
        "mov rsp, rbx",
        // push the arguments of Rawsyscall from the stack to preserved registers
        "mov QWORD PTR [rsp], r11",
        "mov r9, r8",
        "mov r8, rsi",
        "mov rsi, r13",
        "mov rdx, rcx",
        "mov rcx, r10",
        "mov rdi, r12",
        "call c_abi_syscall6_handler",
        // Switch stack back v1
        // "mov    rdi, QWORD PTR [rsp+0x30]",
        // "mov    rsi, QWORD PTR [rdi+0x8]",
        // "sub    rsi, QWORD PTR [rsp+0x28]",
        // "mov    QWORD PTR fs:0xfffffff8, rdi",
        // "mov    rsp, rsi",
        // Switch stack back v2
        "mov rdi, QWORD PTR FS:[0xfffffff8]",
        "mov rbx, QWORD PTR [rdi + 0x30]",
        "mov rdi, QWORD PTR [rbx + 0xc0]",
        "mov QWORD PTR FS:[0xfffffff8], rdi",
        "mov rsp, QWORD PTR [rdi + 0x38]",
        "mov qword ptr [rdi + 0x38], 0x0",
        // Regular flow
        "cmp    rax, -0xfff",
        "jbe    3f",
        "neg    rax",
        "mov    rcx, rax",
        "mov    rax, -0x1",
        "mov    rbx, 0x0",
        "xorps  xmm15, xmm15",
        "mov    r14, QWORD PTR FS:[0xfffffff8]",
        "ret",
        // same as `nosave` in the asmcgocall.
        // calls the abi handler, when we have no g
        "2:",
        "sub    rsp, 0x40",
        "and    rsp, -0x10",
        "mov    QWORD PTR [rsp+0x30], 0x0",
        "mov    QWORD PTR [rsp+0x28], rdx",
        // Call ABI handler
        "mov QWORD PTR [rsp], r9",
        "mov r9, r8",
        "mov r8, rsi",
        "mov rsi, rbx",
        "mov rdx, rcx",
        "mov rcx, r10",
        "mov rdi, rax",
        "call c_abi_syscall6_handler",
        // restore
        "mov    rsi, QWORD PTR [rsp+0x28]",
        "mov    rsp, rsi",
        // Regular flow
        "cmp    rax, -0xfff",
        "jbe    3f",
        "neg    rax",
        "mov    rcx, rax",
        "mov    rax, -0x1",
        "mov    rbx, 0x0",
        "xorps  xmm15, xmm15",
        "mov    r14, QWORD PTR FS:[0xfffffff8]",
        "ret",
        // ???
        "35:",
        "mov QWORD PTR [rsp], r9",
        "mov r9, r8",
        "mov r8, rsi",
        "mov rsi, rbx",
        "mov rdx, rcx",
        "mov rcx, r10",
        "mov rdi, rax",
        "jmp c_abi_syscall6_handler",
        "36:",
        "int 0x3",
        "int3",
        "3:",
        // RAX already contains return value
        "mov    rbx, 0x0",
        "mov    rcx, 0x0",
        "xorps  xmm15, xmm15",
        "mov    r14, QWORD PTR FS:[0xfffffff8]",
        "ret",
        options(noreturn)
    )
}

/// [Naked function] maps to gasave_systemstack_switch, called by asmcgocall.abi0
#[no_mangle]
#[naked]
unsafe extern "C" fn go_systemstack_switch() {
    asm!(
        "lea    r9, [rip+0xdd9]",
        "mov    QWORD PTR [r14+0x40],r9",
        "lea    r9, [rsp+0x8]",
        "mov    QWORD PTR [r14+0x38],r9",
        "mov    QWORD PTR [r14+0x58],0x0",
        "mov    QWORD PTR [r14+0x68],rbp",
        "mov    r9, QWORD PTR [r14+0x50]",
        "test   r9, r9",
        "jz     4f",
        "call   go_runtime_abort",
        "4:",
        "ret",
        options(noreturn)
    );
}

/// [Naked function] maps to runtime.abort.abi0, called by `go_systemstack_switch`
#[no_mangle]
#[naked]
unsafe extern "C" fn go_runtime_abort() {
    asm!("int 0x3", "jmp go_runtime_abort", options(noreturn));
}

#[ctor]
fn init() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    info!("Initializing layer");

    let mut interceptor = Interceptor::obtain(&GUM);

    interceptor.begin_transaction();
    let modules = Module::enumerate_modules();
    let binary = &modules.first().unwrap().name;
    let function =
        Module::find_symbol_by_name(binary, "runtime/internal/syscall.Syscall6").unwrap();

    let _ = interceptor
        .replace(
            function,
            frida_gum::NativePointer(go_syscall_new_detour as *mut libc::c_void),
            frida_gum::NativePointer(std::ptr::null_mut::<libc::c_void>()),
        )
        .unwrap();
    interceptor.end_transaction();
}
