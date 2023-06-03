#!/usr/bin/python3

import argparse
import subprocess

import src.xmltollvm as xmltollvm
import src.lifting_opt_verify as opt_verify

import tomli

# These shouldn't need to be changed
prj_name = "lifting"
xml_script = "./src/GhidraToXML.java"

# Argument parsing
parser = argparse.ArgumentParser(description = 'This script lifts a binary from executable to LLVM IR.')
parser.add_argument('input_file', action='store')
parser.add_argument('-out', action='store_true', help='emit intermediate files', default=False, dest='out')
parser.add_argument('-opt', action='store', help='select optimization level 0-3', default=None, dest='opt')
parser.add_argument('-cfg', action='store_true', help='emit cfg', default=False, dest='cfg')
results = parser.parse_args()

# Parse settings file
with open("settings.toml", mode="rb") as f:
    config = tomli.load(f)

# Check arguments
if results.opt is not None:
    opt_level = int(results.opt)
    if opt_level not in range(4):
        raise argparse.ArgumentTypeError("%s is an invalid optimization level, 0-3 only" % opt_level)
else:
    opt_level = results.opt

# Convert P-code to XML
subprocess.run([config["ghidra_dir"] + "/support/analyzeHeadless", config["project_dir"], prj_name, '-import', results.input_file,
                '-postScript', xml_script, '-overwrite', '-deleteProject'])
filename = results.input_file.split('/')[-1]
xmlfile = './' + filename + '.xml'
subprocess.run(['mv', '/tmp/output.xml', xmlfile])

# Lift to LLVM
module = xmltollvm.lift(xmlfile)
llvmlitefile = str(filename + '.llvmlite')
f = open(llvmlitefile, 'w')
f.write(str(module))
f.close()

# Optimization passes
module = opt_verify.optimize(module, opt_level)

# Verify
module = opt_verify.verify(module)
llfile = str(filename + '.ll')
f = open(llfile, 'w')
f.write(str(module))
f.close()

# Output CFGs
if results.cfg:
    subprocess.run(['rm', '-rf', "graphs"])
    subprocess.run(['mkdir', "graphs"])
    graphs = opt_verify.graph(module)


# Cleanup
if not results.out:
    subprocess.run(['rm', xmlfile])
    subprocess.run(['rm', llvmlitefile])