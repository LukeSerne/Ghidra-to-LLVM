#!/usr/bin/python3
import subprocess
import pathlib
import traceback
import sys

import llvmlite.binding
import tomli

import xmltollvm


# Various paths
BASE_DIR = pathlib.Path(__file__).parent.parent
TESTS_DIR = BASE_DIR / "tests"
GRAPHS_DIR = TESTS_DIR / "graphs"
LLVM_DIR = TESTS_DIR / "llvm"
OBJ_DIR = TESTS_DIR / "obj"
PROJECT_NAME = "testing.gpr"
XML_DIR = TESTS_DIR / "xml"
XML_SCRIPT_DIR = BASE_DIR / "src"
XML_SCRIPT_NAME = "GhidraToXML.java"

def get_config() -> dict[str, str]:
    with open(BASE_DIR / "settings.toml", mode="rb") as f:
        return tomli.load(f)

def main():
    render_cfg = "--graph" in sys.argv
    make_clean = "--clean" in sys.argv
    refresh_cache = make_clean or ("--refresh" in sys.argv)

    config = get_config()

    GHIDRA_PROJECT_DIR = pathlib.Path(config["project_dir"])
    GHIDRA_DIR = pathlib.Path(config["ghidra_dir"])
    HEADLESS_ANALYZER = GHIDRA_DIR / "support" / "analyzeHeadless"

    # Make some dirs if they don't exist already
    for dir_ in (OBJ_DIR, XML_DIR, GRAPHS_DIR, LLVM_DIR):
        if not dir_.exists():
            dir_.mkdir()

    print("[i] Compiling tests")
    if make_clean:
        subprocess.run(["make", "-C", str(TESTS_DIR), "clean"], check=True)

    subprocess.run(["make", "-C", str(TESTS_DIR), "all"], check=True)

    # Initialise the LLVM bindings
    llvmlite.binding.initialize()
    llvmlite.binding.initialize_native_target()
    llvmlite.binding.initialize_native_asmprinter()

    num_failed = 0

    for i, filepath in enumerate(OBJ_DIR.iterdir()):
        filename = filepath.name
        print(f"[i] Processing {filename!r} (#{i})")

        xml_path = (XML_DIR / filename).with_suffix(".xml")

        if xml_path.exists() and refresh_cache:
            xml_path.unlink()

        if not xml_path.exists():
            print(f"[i] Analysing {filepath!r}")
            subprocess.run([
                HEADLESS_ANALYZER, GHIDRA_PROJECT_DIR, PROJECT_NAME,
                "-import", filepath, "-scriptPath", XML_SCRIPT_DIR,
                "-postScript", XML_SCRIPT_NAME, xml_path
            ], check=True, capture_output=True)

        print(f"[i] Lifting {xml_path!r}")

        try:
            lift_out = xmltollvm.lift(xml_path)
        except Exception:
            traceback.print_exc()
            print(f"[!] Test failed!")
            num_failed += 1
            continue

        # Convert to module ref
        mod_ref = llvmlite.binding.parse_assembly(str(lift_out))

        # Verify correctness
        verified_module = llvmlite.binding.parse_bitcode(mod_ref.as_bitcode())
        verified_module.verify()

        with open(LLVM_DIR / (filename + ".ll"), "w", encoding="utf-8") as f:
            f.write(str(verified_module))

        # Render CFG to graph dir
        if render_cfg:
            graph(mod_ref)

    print(f"[i] DONE! ({num_failed} failed)")

def graph(module_ref) -> list[str]:
    """
    Renders control flow graphs for all functions in the given module ref.
    Returns a list of the paths of the generated image files. For every function,
    one PNG files is created and stored inside the graphs folder.
    """
    images = []

    for func in module_ref.functions:
        # Don't graph fake functions that seem to just exist to fill gaps in the
        # lifter implementation
        if func.name in {"intra_function_branch", "call_indirect", "special_subpiece", "bit_extraction"}: continue
        # Don't graph LLVM intrinsics
        if func.name.startswith("llvm.ctpop.") or func.name.startswith("llvm.sadd.with.overflow.") or func.name.startswith("llvm.uadd.with.overflow."): continue

        cfg = llvmlite.binding.get_function_cfg(func)
        graph_data = llvmlite.binding.view_dot_graph(cfg, view=False)
        images.append(graph_data.render(filename=func.name, directory=GRAPHS_DIR, cleanup=True, format="png"))

    return images

if __name__ == "__main__":
    main()
