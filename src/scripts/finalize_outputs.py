import subprocess


def finalize_outputs():
    print("[*] Finalizing outputs (charts + README)")

    # Single source of truth
    subprocess.run(
        ["python", "src/scripts/update_readme.py"],
        check=True
    )

    print("[+] Outputs finalized")

if __name__ == "__main__":
    finalize_outputs()
