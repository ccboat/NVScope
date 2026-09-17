# NVScope
NVScope is a optimized vulnerability discovery method with cross-binary source verification for embedded firmware.

### Directories
```
├── README.md
├── elf_finder         #  Tool to discover all elf files in the firmware
├── package            #  Core scripts that implements the main functionality of NVScope
├── variable_backtrack #  Scripts for AST-level variable backtracking in IDA Pro
├── for_pipe.py        #  Python script for generating the prerequisite files required for IDA analysis
├── vul_batch.py       #  Python script for batch processing of multiple binaries in vulnerability detection
└── run.py         #  Python script for processing individual firmware
```


## Getting Started

We need the Python of version 3.11

```bash
pip install -r requirements.txt
```

You can run the run.py script to use NVScope directly for analyzing the target firmware.

```
python run.py firmware_path result_path
```
