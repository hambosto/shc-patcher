# SHC Patcher

SHC Patcher is a Rust tool designed to patch ELF (Executable and Linkable Format) files, particularly those packed with SHC (Shell Script Compiler). This tool can be used to modify specific functions within ELF binaries, potentially bypassing certain security measures or altering program behavior.

## Features

- Supports both 32-bit and 64-bit ELF files
- Automatically detects ELF architecture
- Patches specific functions like `exec`, `system`, `getpid`, and `memcpy`
- Creates a patched version of the input file

## Prerequisites

- Rust programming environment
- `objdump` utility (typically part of the `binutils` package)
- `strings` utility

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/hambosto/shc-patcher-rs.git
   cd shc-patcher-rs
   ```

2. Build the project:
   ```
   cargo build --release
   ```

## Usage

Run the ELF Patcher with the following command:

```
./target/release/elf-patcher <filepath>
```

Replace `<filepath>` with the path to the ELF file you want to patch.

## How it works

1. The tool reads the specified ELF file and extracts its information using `objdump`.
2. It checks if the file is packed with SHC.
3. The patcher identifies the locations of specific function calls in the binary.
4. It then applies patches to these functions, replacing their code with custom instructions.
5. Finally, it saves the patched file with a `.patch` extension in the same directory as the original file.

## Warning

This tool is intended for educational and research purposes only. Modifying executable files can lead to unexpected behavior and may be illegal in some contexts. Use at your own risk and only on files you have permission to modify.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Disclaimer

This tool is provided as-is, without any warranties or guarantees. The authors are not responsible for any misuse or damage caused by this software.
