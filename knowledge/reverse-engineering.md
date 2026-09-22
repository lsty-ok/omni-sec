# Reverse Engineering & Binary Analysis

> Domain: Reverse Engineering, Disassembly, Decompilation & Static/Dynamic Triage
> Classification: SECURITY KNOWLEDGE BASE

## Purpose

Panduan analisis kode biner terkompilasi (ELF, PE, Mach-O, APK, WASM, Bytecode), rekonstruksi algoritma verifikasi flag, dan mitigasi anti-analisis.

---

## 1. Static Decompilation & Binary Triage

### A. Quick Binary Recon Checklist
```bash
# 1. Identifikasi arsitektur, bitness, dan linking
file challenge.bin

# 2. Periksa security hardening & mitigasi
checksec --file=challenge.bin
# Checks: RELRO, Stack Canary, NX (No-Execute), PIE (Position Independent Executable)

# 3. Cari string statis, teks format flag, atau error messages
strings -a -n 6 challenge.bin | grep -iE "flag\{|correct|wrong|password|key"
```

### B. Common CTF Reversing Logic Patterns

1. **String Transformation / XOR Validation:**
   - Input user diproses per byte: `transformed[i] = (input[i] ^ key[i % len(key)]) + offset`.
   - Hasil dibandingkan dengan array byte statis yang tersimpan di binary (`memcmp` / `strcmp`).
   - **Solusi:** Ekstrak array target dari segmen `.rodata` / `.data`, lalu jalankan operasi balik (*inverse operation*).

2. **Custom Virtual Machines (VM Reversing):**
   - Binary mengimplementasikan interpreter bytecode mini dengan opcode kustom (`OP_ADD`, `OP_XOR`, `OP_JMP`).
   - **Solusi:** Petakan struktur instruksi `[opcode, reg1, reg2, imm]`, buat disassembler Python untuk membongkar bytecode VM.

3. **Symbolic Execution (Z3 Solver):**
   - Jika alur validasi memiliki puluhan kondisi matematis rumit (*linear equations* / S-box), gunakan library `z3-solver` di Python daripada membedah alur manual.

---

## 2. Dynamic Analysis & Debugging

### GDB + GEF / Pwndbg Essential Workflow
```text
gdb ./challenge.bin
gef> checksec
gef> info functions
gef> disas main
gef> break *main+42          # Pasang breakpoint di titik pembanding
gef> run <<< "TEST_INPUT"
gef> info registers          # Periksa isi RAX, RBX, RDI, RSI
gef> x/10s $rdi              # Periksa string pada alamat register
```

---

## 3. High-Level Bytecode & Multi-Platform Reversing

| Format | Tooling Decompiler | Fokus Analisis |
|---|---|---|
| **Python `.pyc`** | `pycdc` / `uncompyle6` / `decompyle++` | Rekonstruksi source code Python dari bytecode |
| **Java / Android APK** | `jadx-gui` / `apktool` | Alur validasi di `MainActivity`, native `.so` files (JNI) |
| **.NET / C#** | `dnSpy` / `ILSpy` / `dotPeek` | Decompilation C# bersih mendekati 100% source asli |
| **WebAssembly (`.wasm`)** | `wasm2wat` / `ghidra-wasm` | Text format WAT (S-expressions), linear memory buffers |
| **Go Binaries** | `Ghidra` + `GoReSym` / `IDAGolangHelper` | Pemulihan nama fungsi Go dan package runtime structures |
