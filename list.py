from pathlib import Path

IGNORE_DIRS = {".git", "__pycache__", ".venv", "node_modules", ".mypy_cache", ".pytest_cache"}

def print_tree(root: Path, prefix: str = ""):
    entries = [e for e in root.iterdir() if not e.name.startswith(".") or e.is_dir()]
    entries.sort(key=lambda p: (p.is_file(), p.name.lower()))
    for i, entry in enumerate(entries):
        connector = "└── " if i == len(entries) - 1 else "├── "
        print(prefix + connector + entry.name)
        if entry.is_dir() and entry.name not in IGNORE_DIRS:
            extension = "    " if i == len(entries) - 1 else "│   "
            print_tree(entry, prefix + extension)

if __name__ == "__main__":
    root = Path(".").resolve()
    print(root.name)
    print_tree(root)
