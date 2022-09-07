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


#[naked]
unsafe extern "C" fn go_syscall_new_detour() {
    asm!(
        // Save rdi in r10
        "mov r10, rdi",
        // Save r9 in r11
        "mov r11, r9",
        // Save rax in r12
        "mov r12, rax",
        // save rbx in r13
        "mov r13, rbx",
        // save rcx in r15
        "mov r15, rcx",
        "call enter_syscall",
        // Save stack
        "mov rdx, rsp",
        "mov rdi, qword ptr FS:[0xfffffff8]",
        "cmp rdi, 0x0",
        "jz 1f",
        "mov rax, qword ptr [rdi + 0x30]",
        "mov rsi, qword ptr [rax + 0x50]",
        "cmp rdi, rsi",
        "jz 1f",
        "mov rsi, qword ptr [rax]",
        "cmp rdi, rsi",
        "jz 1f",
        "call gosave_systemstack_switch",
        "mov qword ptr FS:[0xfffffff8], rsi",
        "mov rsp, qword ptr [RSI + 0x38]",
        "sub rsp, 0x40",
        "and rsp, -0x10",
        "mov qword ptr [rsp + 0x30], rdi",
        "mov rdi, qword ptr [RDI + 0x8]",
        "sub RDI, RDX",
        "mov qword ptr [rsp + 0x28], rdi",
        // push the arguments of Rawsyscall from the stack to preserved registers
        "mov QWORD PTR [rsp], r11",
        "mov r9, r8",
        "mov r8, rsi",
        "mov rsi, r13",
        "mov rdx, r15",
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
        "mov rdi, qword ptr [rsp + 0x30]",
        "mov rsi, qword ptr [rdi + 0x8]",
        "sub rsi, qword ptr [ rsp + 0x28]",
        "mov qword ptr fs:[0xfffffff8], rdi",
        "mov rsp, rsi",
        // exit syscall - it clobbers rax so we need to save it
        "mov rbx, rax",
        "call exit_syscall",
        "mov rax, rbx",
        // Regular flow
        "cmp    rax, -0xfff",
        "jbe    2f",
        "neg    rax",
        "mov    rcx, rax",
        "mov    rax, -0x1",
        "mov    rbx, 0x0",
        "xorps  xmm15, xmm15",
        "mov    r14, QWORD PTR FS:[0xfffffff8]",
        "ret",
        // same as `nosave` in the asmcgocall.
        // calls the abi handler, when we have no g
        "1:",
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
        // exit syscall - it clobbers rax so we need to save it
        "mov rbx, rax",
        "call exit_syscall",
        "mov rax, rbx",
        // Regular flow
        "cmp    rax, -0xfff",
        "jbe    2f",
        "neg    rax",
        "mov    rcx, rax",
        "mov    rax, -0x1",
        "mov    rbx, 0x0",
        "xorps  xmm15, xmm15",
        "mov    r14, QWORD PTR FS:[0xfffffff8]",
        "ret",
        "2:",
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
unsafe extern "C" fn gosave_systemstack_switch() {
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


/// Clobbers rax, rcx
#[no_mangle]
#[naked]
unsafe extern "C" fn enter_syscall() {
    asm!(
        "mov rax, qword ptr [r14 + 0x30]", // get mp
        "inc qword ptr [ rax + 0x130 ]", // inc cgocall
        "inc qword ptr [ rax + 0x138 ]", // inc cgo
        "mov rcx, qword ptr [ rax + 0x140 ]",
        "mov qword ptr [rcx], 0x0", // reset traceback
        "mov byte ptr [ RAX + 0x118], 0x1", // incgo = true
        "ret",
        options(noreturn)
    );
}


/// clobbers xmm15, r14, rax
#[no_mangle]
#[naked]
unsafe extern "C" fn exit_syscall() {
    asm!(
        "xorps xmm15, xmm15",
        "mov r14, qword ptr FS:[0xfffffff8]",
        "mov rax, qword ptr [r14 + 0x30]",
        "dec qword ptr [ rax + 0x138 ]", // dec cgo
        "mov byte ptr [ RAX + 0x118], 0x0", // incgo = false
        "ret",
        options(noreturn)
    );
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
