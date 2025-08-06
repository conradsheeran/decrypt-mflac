import frida
import os
import hashlib
from pathlib import Path
import glob

try:
    session = frida.attach("QQMusic.exe")
    script = session.create_script(open("hook_qq_music.js", "r", encoding="utf-8").read())
    script.load()
except frida.ProcessNotFoundError:
    print("Error: QQMusic.exe process not found. Please make sure QQ Music is running")
    exit()
except Exception as e:
    print(f"Error: {e}")
    exit()

output_dir = Path("output")
output_dir.mkdir(exist_ok=True)


base_search_path = Path.home() / "Music" / "VipSongsDownload"

# 支持通配符 *, ?, []
path_pattern = "Ariana Grande*"

full_pattern = str(base_search_path / path_pattern)
print(f"\nSearching for directories matching pattern: {full_pattern}\n")
target_dirs = [Path(p) for p in glob.glob(full_pattern) if os.path.isdir(p)]

if not target_dirs:
    print(f"No directories found matching '{path_pattern}'")
else:
    print("Found the following matching directories:")
    for d in target_dirs:
        print(f" - {d}")

# 4. 遍历所有找到的目录
for target_dir in target_dirs:
    print(f"\n--- Processing directory: {target_dir} ---")
    # 遍历目录下的所有文件
    for root, dirs, files in os.walk(target_dir):
        for file in files:
            original_file_path = Path(root) / file

            # 只处理 .mflac 和 .mgg 文件
            if original_file_path.suffix in [".mflac", ".mgg"]:
                print(f"Preparing to decrypt: {file}")

                # 修改文件扩展名
                if original_file_path.suffix == ".mflac":
                    new_suffix = ".flac"
                else:
                    new_suffix = ".ogg"

                new_filename = original_file_path.stem + new_suffix
                output_file_path = output_dir / new_filename

                # 检查解密文件是否已经存在
                if output_file_path.exists():
                    print(f"File {output_file_path} already exists")
                    continue

                # 创建唯一的临时文件名，防止冲突
                tmp_file_name = hashlib.md5(file.encode()).hexdigest()
                tmp_file_path = output_dir / tmp_file_name

                try:
                    script.exports_sync.decrypt(str(original_file_path.resolve()), str(tmp_file_path.resolve()))

                    # 重命名临时文件
                    os.rename(tmp_file_path, output_file_path)
                    print(f"  -> Decryption successful, saved as: {output_file_path}")
                except Exception as e:
                    print(f"  -> Error decrypting file {file}: {e}")
                    if tmp_file_path.exists():
                        tmp_file_path.unlink()

# 分离会话
print("\nAll files processed, detaching session.")
session.detach()