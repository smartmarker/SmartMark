# **SmartMark - Software Watermarking Scheme for Smart Contracts**

*SmartMark* is a novel software watermarking scheme, aiming to protect the ownership of a smart contract against a pirate activity.

This repository contains the *SmartMark* program implemented in Python and the dataset used in the paper published at **ICSE 2023**. Please refer to our paper for the details of design and empirical results.

## Authors

Taeyoung Kim <[tykim0402@skku.edu](mailto:tykim0402@skku.edu)> *- Sungkyunkwan University*

Yunhee Jang <[unijang@skku.edu](mailto:unijang@skku.edu)> *- Sungkyunkwan University*

Chanjong Lee <[leecj323@skku.edu](mailto:leecj323@skku.edu)> *- Sungkyunkwan University*

Hyungjoon Koo <[kevin.koo@skku.edu](mailto:kevin.koo@skku.edu)> *- Sungkyunkwan University*

Hyoungshick Kim <[hyoung@skku.edu](mailto:hyoung@skku.edu)> *- Sungkyunkwan University*

---
<br>

## Requirements

To execute the *SmartMark* program, the pycryptodome python package needs to be installed. The installation command is as follows:

```bash
pip3 install pycryptodome
```

We have confirmed that *SmartMark* can be executed on a 64-bit Ubuntu 18.04 system with Python3.9.


## Installation

```bash
git clone https://github.com/smartmarker/SmartMark.git
cd SmartMark/SmartMark
python3 main.py [flags]
```

<br>

## How to use SmartMark

```bash
SmartMark
    .
    |--- main.py              // Program entry
    |--- EmbedWatermark.py    // 
    |--- VerifyWatermark.py
    |--- ErrorHandler.py
    |--- samples
```

*SmartMark* can be run with the `python3 main.py [flags]` command.

**Arguments:**

```bash
usage: main.py [-h] [-I CFG] [-W WRO] [-M WROMAC] [-V RESULT] [-B CFG_BUILDER] [-R BIN_RUNTIME] [-L LENGTH] [-N NUMBER]
               [-c GASCOST] [-r RATIO] [-o MAXOPNUM]

optional arguments:
  -h, --help            show this help message and exit
  -I CFG, --CFG CFG     path of a CFG json file
  -W WRO, --WRO WRO     path of a WRO file *required for verification*
  -M WROMAC, --WROMAC WROMAC
                        path of a WRO MAC file *required for verification*
  -V RESULT, --result RESULT
                        path of a file that contains the verification result
  -B CFG_BUILDER, --CFG_builder CFG_BUILDER
                        path of the EtherSolve control flow graph builder
  -R BIN_RUNTIME, --bin_runtime BIN_RUNTIME
                        path of a runtime bytecode to build control flow graph
  -L LENGTH, --length LENGTH
                        the length of watermark *required for embedding*
  -N NUMBER, --number NUMBER
                        the number of watermark *required for embedding*
  -c GASCOST, --gasCost GASCOST
                        a minumum gas cost for opcode group (default: 9)
  -r RATIO, --ratio RATIO
                        a opcode group ratio (default: 20)
  -o MAXOPNUM, --maxOpNum MAXOPNUM
                        a max opcode number for opcode grouping (default: 5)
```

### 1. **execution mode**

First, it asks which mode to be run (i.e., watermark embedding mode or verification mode) with the message below:

```markdown
Do you wanna embed or verify the watermark(s)? (embed:1, verify:0) [0/1] : !your answer here!
```

- If selected 1 (embed), it calls the EmbedWatermark module afterwards
- If selected 0 (verify), it calls the VerifyWatermark module afterwards

The required inputs depends on the currently selected mode.

- **Embedding mode**
    - the length of the watermark(s) (flag: -L or —length)
    - the number of the watermark(s) (flag: -N or —number)
    - [optional] path of a WRO output file (flag: -W or —WRO)
    - [optional] path of a WROMAC output file (flag: -M or —WROMAC)
- **Verification mode**
    - path of a WRO input file (flag: -W or —WRO)
    - path of a WROMAC input file (flag: -M or —WROMAC)
    - [optional] path of a output file that contains the verification result (flag: -V or —result)

✅ The optional flags are related to the paths of the output files. If those paths are not given, the output files are saved in the SmartMark_output directory by default.

### 2. control flow graph (CFG) construction

Second, it checks whether the CFG construction needs to be performed before embed or verify the watermark(s) with the message below:

```markdown
Build CFG from a runtime bytecode? (It you already have one, just select 'n') [y/n] : !your answer here!
```

❗Note: SmartMark requires the CFG to watermark a contract and it only supports the EtherSolve CFG builder for now.

If the only one you have is a **contract runtime bytecode**, select ‘y’ and submits

- path of the EtherSolve control flow graph builder in your system (flag: -B or —CFG_builder)
- path of a runtime bytecode to build control flow graph (flag: -R or —bin_runtime)
- [optional] path of a CFG json output file

Otherwise if you already have a **JSON-format** **CFG built by EtherSolve**, select ‘n’ and submits

- path of a CFG json input file (flg: -I or —CFG)

<br>

---

## Dataset

We provide the smart contract dataset involved in our experiments (Section VI).

```bash
dataset
    .
    |--- runtime_bytecodes_27824
    |--- CFG_jsons_27824    
    |--- Solidity_codes_9324
```

### **runtime_bytecodes_27824**

This dataset contains the runtime bytecodes of 27,824 unique smart contracts. 
For this, we collected a total of 4,112,336 contract runtime bytecodes from the fifteen million Ethereum Mainnet blocks (deployed between 30 July 2015 to 21 June 2022), and performed DBSCAN clustering to exclude the clone contracts.

### **CFG_jsons_27824**

This dataset contains the 27,824 JSON-format CFG files built from the above runtime bytecode dataset using EtherSolve tool.

### **Solidity_codes_9324**

This dataset contains the 9,324 Solidity source codes for the contracts that have publicly released source codes among the above 27,824 contracts. We collected these codes by crawling EtherScan.
In EtherScan, even for a single contract address, there would be multiple Solidity source codes consisting of multiple contracts that are in a inheritance relationship. For successful compilation, we collected all source codes for each address, and sorted them in the order of inheritance in a single file, and also we removed all unnecessary instructions, such as annotations, *import* instructions, and redundant pragma versions.
