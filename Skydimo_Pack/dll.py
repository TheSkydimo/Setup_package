# -*- coding: utf-8 -*-
import os
import sys
from typing import List


DEFAULT_TIMESTAMP_URL = "http://timestamp.digicert.com"
DEFAULT_DIGEST_ALGORITHM = "SHA256"


def locate_dll_directory(base_dir: str) -> str:
    dll_dir = os.path.join(base_dir, "dll")
    return dll_dir


def find_dll_files(dll_dir: str) -> List[str]:
    if not os.path.isdir(dll_dir):
        return []
    dll_files: List[str] = []
    for entry in os.listdir(dll_dir):
        if entry.lower().endswith(".dll"):
            dll_files.append(os.path.abspath(os.path.join(dll_dir, entry)))
    dll_files.sort()
    return dll_files


def sign_with_signtool(file_path: str, timestamp_url: str, digest_algorithm: str) -> None:
    """Fallback signer when importing SignBat.sign_file is not available."""
    current_dir = os.path.dirname(os.path.abspath(__file__))
    signtool_path = os.path.abspath(os.path.join(current_dir, "..", "signtool.exe"))
    if not os.path.isfile(signtool_path):
        print(f"Error: signtool.exe not found at {signtool_path}")
        return
    cmd = [
        signtool_path,
        "sign",
        "/v",
        "/as",
        "/fd",
        digest_algorithm,
        "/n",
        "Shenzhen Light Universe Technology Co., Ltd.",
        "/tr",
        timestamp_url,
        "/td",
        "sha256",
        "/d",
        "Skydimo Setup — PC Ambient Lighting Controller",
        "/du",
        "https://www.skydimo.com",
        os.path.abspath(file_path),
    ]
    print("Running command:", " ".join(cmd))
    try:
        import subprocess

        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        if result.stdout:
            print(result.stdout)
        if result.stderr:
            print(result.stderr)
    except Exception as e:
        print("Error executing signtool:", repr(e))


def sign_single_file(file_path: str, timestamp_url: str, digest_algorithm: str) -> None:
    try:
        from SignBat import sign_file as sign_executable_file
    except Exception:
        sign_executable_file = None
    if sign_executable_file:
        sign_executable_file(file_path, timestamp_url, digest_algorithm)
    else:
        sign_with_signtool(file_path, timestamp_url, digest_algorithm)


def main() -> None:
    base_dir = os.path.dirname(os.path.abspath(__file__))
    dll_dir = locate_dll_directory(base_dir)
    if not os.path.isdir(dll_dir):
        print(f"Error: DLL directory not found: {dll_dir}")
        sys.exit(1)

    dll_files = find_dll_files(dll_dir)
    if not dll_files:
        print(f"No .dll files found in {dll_dir}")
        sys.exit(0)

    print(f"Found {len(dll_files)} .dll file(s) in {dll_dir}. Starting code signing...")
    timestamp_url = DEFAULT_TIMESTAMP_URL
    digest_algorithm = DEFAULT_DIGEST_ALGORITHM

    for file_path in dll_files:
        print(f"Signing: {file_path}")
        sign_single_file(file_path, timestamp_url, digest_algorithm)

    print("DLL code signing completed.")


if __name__ == "__main__":
    main()


