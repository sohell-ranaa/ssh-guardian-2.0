import os

def show_structure(path=".", prefix="", exclude=["venv", ".git", "__pycache__", ".vscode", "node_modules"]):
    items = sorted(os.listdir(path))
    dirs = [i for i in items if os.path.isdir(os.path.join(path, i)) and i not in exclude]
    files = [i for i in items if os.path.isfile(os.path.join(path, i))]
    
    # Show files first
    for i, file in enumerate(files):
        is_last = (i == len(files) - 1) and len(dirs) == 0
        print(f"{prefix}{'└──' if is_last else '├──'} {file}")
    
    # Show directories
    for i, dir_name in enumerate(dirs):
        is_last = (i == len(dirs) - 1)
        print(f"{prefix}{'└──' if is_last else '├──'} {dir_name}/")
        new_prefix = prefix + ("    " if is_last else "│   ")
        show_structure(os.path.join(path, dir_name), new_prefix, exclude)

# Get current directory
current_dir = os.getcwd()
print(f"📁 Project Structure from: {current_dir}\n")
print(f"{os.path.basename(current_dir)}/")
show_structure(".")