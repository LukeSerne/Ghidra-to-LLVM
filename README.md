# Ghidra-to-LLVM
This program lifts a compiled binary via Ghidra PCODE to LLVM IR. This fork of
[the original Ghidra-to-LLVM project](https://github.com/toor-de-force/Ghidra-to-LLVM)
intends to complete the missing PCODE operations, add support for the PCODE used
in the latest Ghidra version, add more tests for complex programs and functions,
and add complete support for architectures other than `x86_64`.

## Acknowledgements
A large number of the tests currently included with this repository were created
as part of the [Pharos framework](https://github.com/cmu-sei/pharos), developed by [Carnegie Mellon University's Software Engineering Institute](https://www.sei.cmu.edu/).

## Setup
This is a Python 3 program, and it also requires `make` to be installed to
compile the tests. If you just want to run the program and don't care about the
tests, you only need Python 3 and the modules `llvmlite` and `tomli` (and
`graphviz` to render control flow graphs). These dependencies can be easily
installed using `python -m pip install -r requirements.txt`.

## Install

1. Make sure you have Ghidra installed. Installation guide can be found [here](https://github.com/NationalSecurityAgency/ghidra/tree/master#install).
2. Copy and adjust `example_settings.toml` to your system. Set `ghidra_dir` to
   a path to the folder in which you installed Ghidra. Set `project_dir` to a
   folder in which the ghidra project can be placed. If no `project_dir` is
   specified, a new temporary folder will be created and used every time the
   script is ran.

## Usage
To run the program for a single binary file `input_file`, use `python3 g2llvm.py input_file`.
The full usage can be found in the help message below, which is also available
through `python3 g2llvm.py --help`.

```
python3 g2llvm.py [-h] [-out] [-opt OPT] [-cfg] input_file

positional arguments:
  input_file  the path of the binary file

options:
  -h, --help  show this help message and exit
  -out        emit intermediate files
  -opt OPT    select optimization level 0-3, default 0 (only 0 works)
  -cfg        if set, also creates a PNG of the CFG of all functions in the
              binary in the "graphs" folder
```

If you want to run the tests, make sure you have `make` installed and the
version of `make` you're using supports the `-C` argument to run make from a
different folder. Then, run `python3 src/run-all-tests.py`.

Intermediate files will be created in subfolders of `tests`:
- `tests/graphs` will contain PNG renders of the control flow graph of all
  functions in all tests if the `--graph` argument is given.
- `tests/llvm` will contain a file containing the LLVM IR of a test program for
  each test.
- `tests/obj` will contain the compiled object files.
- `tests/xml` will contain the `.xml` files produced by the custom Ghidra script,
  containing the PCODE and some metadata about the program.

If you want to completely rerun all tests, you should provide the `--clean`
argument. If you want to rerun only the Ghidra analysis and PCODE translation,
you should provide the `--refresh` argument. Note that `--clean` implies `--refresh`.
If you want to only rerun the PCODE translation, no arguments need to be given.

## Workings
This script works by loading the provided binary in Ghidra's headless analyzer
and running the automatic analysis to discover all functions. Then, it goes
through all recovered functions one-by-one, decompiles them and reads the
resulting "high" PCODE. This PCODE is then, along with some metadata about the
registers and memory locations that are used, saved to an `.xml` file.

The script then reads this `.xml` file, iterates through the functions and
translates every PCODE operation into one or multiple LLVM IR instructions and
combines them to create an LLVM module. Next, this module is optimised using
LLVM's optimisations and according to the provided optimisation level. Finally,
the optimised module is written to a `.ll` file, and the unoptimised module is
written to a `.llvmlite` file. Optionally, the control flow graphs of the
optimised module can be rendered as `.png` files and saved to the `graphs`
folder.

## Extra Scripts
There are some extra scripts located in the `extra_scripts` folder.

- `HighFunction_Analysis.java`: Prints a readable version of the high function
  representation.
- `HighFunction2LLVM.java`: Makes an XML file of the the high function
  representation of all functions in a program. This might be a potential earlier
  version of the `src/GhidraToXML.java` file.
