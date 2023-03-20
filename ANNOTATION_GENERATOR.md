# Motivation

 
## Dependencies
 1. Works on a) kernel verion 5.4.0-131, Ubuntu 22:04, Intel arch x86 arch b) Dockerfile works with Wondows 10, WSL2+Docker Desktop with Ubuntu 22.04 App from MS store. There is a known issue with Apple Silicon based Macbooks with installing a) ``gcc-multlib`` b) TXL and c) Codequery, described [here](https://github.com/sdsen/opened_extraction/issues/37)
 2. git
 3. Docker
  
## Install 
### Process 1: Docker
 1. ``mkdir op`` To store the output of extraction phase (or any other folder name)
 2.  ``docker build . -t opened/annotate:0.01``

### Process 2: on host
 1. **For now:** You will need to parse the Dockerfile and execute the installation steps on your host system.
 2. In future we will provide a script for on-host installation ([Issue #24](https://github.com/eBPFDevSecTools/ebpf-projects-annotations/issues/12)).
 
### Annotation Generation

 1. Run the docker. ``docker run -it --privileged --mount type=bind,src=<source_code_dir_on_host>/ebpf-projects-annotations/examples,dst=/root/examples --mount type=bind,src=<source_code_dir_on_host>/ebpf-projects-annotations/op, dst=/root/op opened/annotate:0.01``. Where ``op`` is the folder created in step Install.3 . The output is expected to be dumped in this folder, so that it is available for later processing/use in host system.

2. Run annotator phase1, 
TODO: Expand README to include additional capabilities moved into annotator
```
python3 src/annotator.py
usage: annotator.py [-h] [-annotate_only ANNOTATE_ONLY] -s SRC_DIR -o TXL_OP_DIR [-c OPENED_COMMENT_STUB_FOLDER] [-r BPFHELPERFILE]
                    [-t TXL_FUNCTION_LIST] [-u TXL_STRUCT_LIST] [--isCilium]

optional arguments:
  -h, --help            show this help message and exit
  -annotate_only ANNOTATE_ONLY
  -s SRC_DIR, --src_dir SRC_DIR
                        directory with source code
  -o TXL_OP_DIR, --txl_op_dir TXL_OP_DIR
                        directory to put txl annotated files
  -c OPENED_COMMENT_STUB_FOLDER, --opened_comment_stub_folder OPENED_COMMENT_STUB_FOLDER
                        directory to put source files with comment stub
  -r BPFHELPERFILE, --bpfHelperFile BPFHELPERFILE
                        Information regarding bpf_helper_funcitons
  -t TXL_FUNCTION_LIST, --txl_function_list TXL_FUNCTION_LIST
                        JSON with information regarding functions present. output of foundation_maker.py
  -u TXL_STRUCT_LIST, --txl_struct_list TXL_STRUCT_LIST
                        JSON with information regarding structures present. output of foundation_maker.py
  --isCilium            whether repository is cilium

```

NOTE: **The description given above might be dated, always check examples given in run1.sh for latest capabilities.**
 

