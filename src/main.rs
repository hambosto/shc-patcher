use std::fs::{self, File};
use std::io::{self, Write};
use std::process::Command;

#[derive(Debug)]
struct ELFInfo {
    arch: String,
    dump: String,
    elf: Vec<u8>,
    base: usize,
}

struct ELFPatcher {
    filepath: String,
    elf_info: Option<ELFInfo>,
}

impl ELFPatcher {
    fn new(filepath: String) -> Self {
        ELFPatcher {
            filepath,
            elf_info: None,
        }
    }

    fn read_file(&self) -> io::Result<Vec<u8>> {
        fs::read(&self.filepath)
    }

    fn shell(&self, cmd: &str) -> io::Result<String> {
        let output = Command::new("sh").arg("-c").arg(cmd).output()?;

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    fn get_dump(&mut self) -> bool {
        let elf_header = format!("objdump -h -- {}", self.filepath);
        let res = match self.shell(&elf_header) {
            Ok(r) => r,
            Err(_) => return false,
        };

        if !res.contains("file format elf") {
            return false;
        }

        let strings_check = format!("strings {} | grep \"E: neither\"", self.filepath);
        if self.shell(&strings_check).unwrap_or_default().is_empty() {
            println!("Seems not packed with shc");
            return false;
        }

        let arch = if res.contains("elf32") {
            "ELF32"
        } else {
            "ELF64"
        };
        let objdump = format!("objdump -M intel -d -j .text -- {}", self.filepath);
        let dump = match self.shell(&objdump) {
            Ok(d) => d,
            Err(_) => return false,
        };

        let text_start = res.find(".text").unwrap_or(0);
        let text_info: Vec<&str> = res[text_start..].split_whitespace().collect();
        let base = usize::from_str_radix(text_info[2], 16).unwrap_or(0)
            - usize::from_str_radix(text_info[4], 16).unwrap_or(0);

        self.elf_info = Some(ELFInfo {
            arch: arch.to_string(),
            dump,
            elf: self.read_file().unwrap_or_default(),
            base,
        });

        if let Some(ref info) = self.elf_info {
            println!("File Format: {}", info.arch);
            println!("Base Address: {:x}", info.base);
        }

        true
    }

    fn find_call(&self, func_name: &str, rindex: usize) -> usize {
        if let Some(ref info) = self.elf_info {
            let mut end = info.dump.rfind(func_name).unwrap_or(0);
            for _ in 0..rindex {
                end = info.dump[..end].rfind(func_name).unwrap_or(0);
            }

            let start = info.dump[..end].rfind('\n').map(|i| i + 1).unwrap_or(0);
            end = info.dump[..end].rfind(':').unwrap_or(0);
            let func_offset =
                usize::from_str_radix(&info.dump[start..end].trim(), 16).unwrap_or(0) - info.base;
            println!("call {} at offset: {:x}", func_name, func_offset);
            func_offset
        } else {
            0
        }
    }

    fn patch_func(&mut self, func_name: &str, rindex: usize, replace_code: &str) -> bool {
        let offset = self.find_call(func_name, rindex);
        if offset != 0 {
            let replace_code = if replace_code.is_empty() {
                "90 90 90 90 90"
            } else {
                replace_code
            };
            let patch_code = hex::decode(replace_code.replace(' ', "")).unwrap();
            if let Some(ref mut info) = self.elf_info {
                info.elf.splice(
                    offset..offset + patch_code.len(),
                    patch_code.iter().cloned(),
                );
                println!("Patch {} with {}", func_name, replace_code);
                true
            } else {
                false
            }
        } else {
            false
        }
    }

    fn patch64(&mut self) {
        self.patch_func("exec", 0, "");
        let hard = self.patch_func("system", 0, "");
        if hard {
            self.patch_func("getpid", 1, "B8 01 00 00 00 C9 C3");
            self.patch_func(
                "memcpy",
                0,
                "48 89 FE 48 31 FF FF C7 48 89 F8 0F 05 B8 3C 00 00 00 0F 05",
            );
        } else {
            self.patch_func("getpid", 0, "B8 01 00 00 00 C9 C3");
            self.patch_func(
                "memcpy",
                0,
                "B8 01 00 00 00 89 C7 0F 05 31 C0 B8 3C 00 00 00 0F 05",
            );
        }
    }

    fn patch32(&mut self) {
        self.patch_func("exec", 0, "");
        let hard = self.patch_func("system", 0, "");
        if hard {
            self.patch_func("getpid", 1, "B8 01 00 00 00 C9 C3");
            self.patch_func(
                "memcpy",
                0,
                "B8 04 00 00 00 59 5A 5A 6A 01 5B CD 80 31 C0 40 C9 C3",
            );
        } else {
            self.patch_func("getpid", 0, "B8 01 00 00 00 C9 C3");
            self.patch_func(
                "memcpy",
                0,
                "B8 04 00 00 00 5A 6A 01 5B 59 5A CD 80 31 C0 40 C9 C3",
            );
        }
    }

    fn patch(&mut self) {
        if let Some(ref info) = self.elf_info {
            if info.arch == "ELF64" {
                self.patch64();
            } else {
                self.patch32();
            }
        }
    }

    fn save_patched_file(&self) -> io::Result<()> {
        if let Some(ref info) = self.elf_info {
            let new_path = format!("{}.patch", self.filepath);
            let mut file = File::create(&new_path)?;
            file.write_all(&info.elf)?;
            self.shell(&format!("chmod +x {}", new_path))?;
            println!("Patched file saved as: {}", new_path);
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::Other,
                "ELF info not available",
            ))
        }
    }
}

fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        println!("Usage: {} <filepath>", args[0]);
        return Ok(());
    }

    let filepath = &args[1];
    let mut patcher = ELFPatcher::new(filepath.to_string());

    if !patcher.get_dump() {
        println!("Error in objdump or file not compatible");
        return Ok(());
    }

    patcher.patch();
    patcher.save_patched_file()?;

    Ok(())
}
