import os
import sys
import subprocess
import json
import hashlib
import argparse
from pathlib import Path
import binwalk
from rich.progress import Progress

# 尝试导入外部依赖，兼容脚本直接运行
try:
    from .keyword_finder import find_keywords
    from .elf_info import FS_LIST
except ImportError:
    from keyword_finder import find_keywords
    from elf_info import FS_LIST

class FirmwareFinder:
    """
    The Finder assumes that each Vendor is a top-level directory in the given target directory.
    """

    def __init__(
        self, target_dir: Path, results_dir: Path, bin_prep=False, exclude_libs=True
    ):
        self.target_dir = target_dir.absolute().resolve()
        self.results_dir = results_dir.absolute().resolve()
        self.exclude_libs = exclude_libs
        
        self.results_dir.mkdir(parents=True, exist_ok=True)
        vendor_file = self.results_dir / "vendors.json"
        
        if vendor_file.exists() and not bin_prep:
            try:
                self.vendor_dict = json.loads(vendor_file.read_text(encoding="utf-8", errors="ignore"))
                print(f"[*] Loaded existing vendors.json")
            except json.decoder.JSONDecodeError:
                self.vendor_dict = {}
        else:
            self.vendor_dict = {}

        if bin_prep or not self.vendor_dict:
            new_vendor_dict = self.search()
            self.vendor_dict.update(new_vendor_dict)
            

    def extract_firmware(self, vendor):
        for root, _, files in os.walk(vendor):
            for file in files:
                f = Path(root) / file
                if f.is_file():
                    try:
                        modules = binwalk.scan(str(f), signature=True, quiet=True)
                        if any("filesystem" in x.description for result in modules for x in result.results):
                            binwalk.scan(str(f), signature=True, extract=True, quiet=True)
                    except Exception as e:
                        print(f"[!] Binwalk error on {f.name}: {e}")

    def search(self):
        vendors = [x for x in self.target_dir.iterdir() if x.is_dir()]
        vendor_dict = dict()
        
        with Progress() as progress:
            vendor_task_str = "[red]Scanning Vendor"
            vendor_task = progress.add_task(
                f"{vendor_task_str} ...", total=len(vendors)
            )
            
            for idx, vendor in enumerate(vendors):
                progress.update(
                    vendor_task,
                    description=f"{vendor_task_str} {vendor.name} [{idx}/{len(vendors)}]",
                )
                
                found_fs = self.find_extracted_fs(vendor)
                if not found_fs:
                    self.extract_firmware(vendor)
                    found_fs = self.find_extracted_fs(vendor)
                
                vendor_dict[vendor.name] = {"path": str(vendor), "firmware": dict()}
                
                fs_task_str = "[green]Iterating FS"
                fs_task = progress.add_task(f"{fs_task_str} ...", total=len(found_fs))
                
                for fs_idx, fs in enumerate(found_fs):
                    firm_name = self.firm_name_from_path(fs)
                    
                    if firm_name is None:
                        progress.update(fs_task, advance=1)
                        continue

                    # =================================================
                    # 修复点：捕获关键字查找可能出现的编码错误
                    # =================================================
                    try:
                        keywords = find_keywords(fs, progress=progress)
                    except Exception as e:
                        # print(f"[!] Keyword scan error: {e}") 
                        keywords = {}

                    progress.update(
                        fs_task,
                        description=f"{fs_task_str} {firm_name} [{fs_idx}/{len(found_fs)}]",
                    )
                    
                    elf_dict = self.find_elf_files(
                        fs, progress, exclude_libs=self.exclude_libs
                    )

                    if firm_name in vendor_dict[vendor.name]["firmware"]:
                        vendor_dict[vendor.name]["firmware"][firm_name]["elfs"].update(
                            elf_dict
                        )
                    else:
                        vendor_dict[vendor.name]["firmware"][firm_name] = {
                            "path": str(fs.parent),
                            "elfs": elf_dict,
                        }

                    safe_vendor_name = vendor.name.replace("/", "_").replace("\\", "_")
                    safe_firm_name = firm_name.replace("/", "_").replace("\\", "_")

                    vendor_json_path = self.results_dir / f"vendor.json"
                    keywords_json_path = self.results_dir / f"keywords.json"

                    try:
                        with vendor_json_path.open("w+", encoding="utf-8") as f:
                            json.dump(
                                vendor_dict[vendor.name]["firmware"][firm_name], f, indent=4
                            )
                        with keywords_json_path.open("w+", encoding="utf-8") as f:
                            json.dump(keywords, f, indent=4)
                    except Exception as e:
                        print(f"[!] Error writing JSON for {firm_name}: {e}")
                        
                    progress.update(fs_task, advance=1)

                progress.update(fs_task, visible=False)
                progress.update(vendor_task, advance=1)
                
        return vendor_dict

    @staticmethod
    def firm_name_from_path(path: Path):
        if path.parent.name == "fw" or path.parent.name == "firmware":
            path = path.parent
        firm_name = (
            path.parent.name.replace(".bin", "")
            .replace(".extracted", "")
            .replace(".chk", "")
            .strip("_")
        )
        black_list = ["functions", "kernel", "qemu", "net", "squashfs-root"]
        if "qemu" in firm_name.lower() or firm_name.lower() in black_list:
            return None
        return firm_name

    @staticmethod
    def find_extracted_fs(root_dir: Path):
        found_fs = []
        for fs in FS_LIST:
            command = ["find", str(root_dir), "-type", "d", "-name", f"{fs}*"]
            try:
                # =================================================
                # 修复点：添加 errors="ignore" 以跳过乱码路径
                # =================================================
                output = subprocess.check_output(command).decode("utf-8", errors="ignore")
                current_fs = [Path(x) for x in output.split("\n") if x]
                found_fs.extend(current_fs)
            except subprocess.CalledProcessError:
                continue
            except Exception as e:
                print(f"[!] FS Find Error: {e}")
        return found_fs

    @staticmethod
    def find_elf_files(root_dir: Path, progress, exclude_libs=True):
        BANNED_LIST = ["busybox"]
        elf_task_str = "[cyan]Finding ELFs"
        elf_task = progress.add_task(f"{elf_task_str} ...", total=None)
        
        try:
            # =================================================
            # 修复点：添加 errors="ignore" 以处理 file 命令的二进制输出
            # =================================================
            output = subprocess.check_output(
                ["find", str(root_dir), "-type", "f", "-exec", "file", "{}", ";"]
            ).decode("utf-8", errors="ignore")
            
            elfs = [
                x
                for x in output.split("\n")
                if "ELF" in x and (not exclude_libs or "shared object" not in x)
            ]
        except subprocess.CalledProcessError:
            elfs = []
        except Exception:
            elfs = []

        progress.update(
            elf_task, description=f"{elf_task_str} [0/{len(elfs)}]", total=len(elfs)
        )
        progress.start_task(elf_task)
        
        elf_dict = {}
        for idx, elf in enumerate(elfs):
            try:
                # 提取文件路径
                path_str = elf.split(":")[0].strip()
                path = Path(path_str)
                
                if path.is_symlink():
                    continue
                if path.name in BANNED_LIST:
                    continue
                
                with path.open("rb") as f:
                    sha256 = hashlib.file_digest(f, "sha256").hexdigest()
                    elf_dict[sha256] = {"path": str(path)}
            except (PermissionError, FileNotFoundError, OSError):
                # 乱码路径可能导致 FileNotFoundError，直接跳过
                pass

            progress.update(
                elf_task, description=f"{elf_task_str} [{idx+1}/{len(elfs)}]", advance=1
            )
        progress.update(elf_task, visible=False)

        return elf_dict


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Firmware Finder: Scan and extract ELF files (Robust Encoding).")
    
    parser.add_argument("target_dir", type=Path, help="Input directory containing firmware images")
    parser.add_argument("result_dir", type=Path, help="Output directory for JSON results")
    parser.add_argument("--bin-prep", action="store_true", help="Force rescan and ignore existing vendors.json")
    parser.add_argument("--include-libs", action="store_true", help="Include .so shared libraries in scan")

    args = parser.parse_args()

    if not args.target_dir.exists():
        print(f"[!] Target directory not found: {args.target_dir}")
        sys.exit(1)

    try:
        print(f"[*] Starting scan on: {args.target_dir}")
        finder = FirmwareFinder(
            target_dir=args.target_dir,
            results_dir=args.result_dir,
            bin_prep=args.bin_prep,
            exclude_libs=not args.include_libs 
        )
        print("[+] Scan completed.")
        
    except KeyboardInterrupt:
        print("\n[!] User interrupted.")
    except Exception as e:
        # 打印错误堆栈以方便调试
        import traceback
        traceback.print_exc()
        print(f"\n[!] Critical Error: {e}")
