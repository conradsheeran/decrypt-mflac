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
    print("错误：未找到 QQMusic.exe 进程。请确保 QQ 音乐正在运行")
    exit()
except Exception as e:
    print(f"错误：{e}")
    exit()

output_dir = Path("output")
output_dir.mkdir(exist_ok=True)


base_search_path = Path.home() / "Music" / "VipSongsDownload"

# 支持通配符 *, ?, []
path_pattern = "Ariana Grande*"

full_pattern = str(base_search_path / path_pattern)
print(f"\n正在搜索匹配模式的目录: {full_pattern}")
target_dirs = [Path(p) for p in glob.glob(full_pattern) if os.path.isdir(p)]

if not target_dirs:
    print(f"未找到任何匹配 '{path_pattern}' 的目录")
else:
    print("找到以下匹配目录:")
    for d in target_dirs:
        print(f" - {d}")

# 4. 遍历所有找到的目录
for target_dir in target_dirs:
    print(f"\n--- 正在处理目录: {target_dir} ---")
    # 遍历目录下的所有文件
    for root, dirs, files in os.walk(target_dir):
        for file in files:
            # 使用 pathlib 处理路径，更现代化且跨平台
            original_file_path = Path(root) / file

            # 只处理 .mflac 和 .mgg 文件
            if original_file_path.suffix in [".mflac", ".mgg"]:
                print(f"准备解密: {file}")

                # 修改文件扩展名
                if original_file_path.suffix == ".mflac":
                    new_suffix = ".flac"
                else:
                    new_suffix = ".ogg"

                new_filename = original_file_path.stem + new_suffix
                output_file_path = output_dir / new_filename

                # 检查解密文件是否已经存在
                if output_file_path.exists():
                    print(f"文件 {output_file_path} 已存在")
                    continue

                # 创建唯一的临时文件名，防止冲突
                tmp_file_name = hashlib.md5(file.encode()).hexdigest()
                tmp_file_path = output_dir / tmp_file_name

                try:
                    script.exports_sync.decrypt(str(original_file_path.resolve()), str(tmp_file_path.resolve()))

                    # 重命名临时文件
                    os.rename(tmp_file_path, output_file_path)
                    print(f"  -> 解密成功，已保存为: {output_file_path}")
                except Exception as e:
                    print(f"  -> 解密文件 {file} 时发生错误: {e}")
                    if tmp_file_path.exists():
                        tmp_file_path.unlink()

# 分离会话
print("\n所有文件处理完毕，分离会话。")
session.detach()