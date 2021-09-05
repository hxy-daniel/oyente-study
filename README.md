Oyente
======

## Notice
1. solc version `v0.4.19`

1. evm version `v1.7.3`/`v1.8.2-v1.8.16` `v1.8.17+`evm disasm has changed which appears to cause issues with the tokenizer 

```
git clone go-ethereum
git checkout v1.8.2
make all (build instructions include evm and so on, GO111MODULE=off, or make fail)
vim ~/.bashrc
add /build/bin to path
```

1. crytic-compile `v0.1.13` the latest version has some question(not compatible with oyente).

## 原理分析
1. 全局参数设置
1. 命令行参数设置
1. logger设置
1. `-s`指定合约文件或`-ru`指定远程合约文件
1. 调用analyze_solidity()
2. inputs = InputHelper(...).get_inputs(...) 生成.evm和.evm.disasm文件，获取合约信息用于分析
    inputs
    ```
    {
        'contract': '/home/daniel/paper/oyente/remote_contract.sol:Puzzle', 
        'source_map': SourceMap对象, 
        'source': 'remote_contract.sol', 
        'c_source': '/home/daniel/paper/oyente/remote_contract.sol', 
        'c_name': 'Puzzle', 
        'disasm_file': '/home/daniel/paper/oyente/remote_contract.sol:Puzzle.evm.disasm'
    }
    ```

    source_map
    ```
    {
        'allow_path': '',
        'ast_helper': AstHelper对象,
        'callee_src_pairs': [],
        'cname': 'remote_contract.sol:Puzzle',
        'func_call_name': ['bytes32(11111)', 'owner.send(reward)', 'sha256(msg.data)', 'msg.sender.send(reward)'],
        'func_name_to_params': {},
        'func_to_sig_by_contract': {
            'remote_contract.sol:Puzzle': {
                'hashes': {
                    'diff()': 'a0d7afb7', 'locked()': 'cf309012', 'owner()': '8da5cb5b', 'reward()': '228cb733', 'solution()': '4fb60251'
                }
            }
        },
        'input_type': 'solidity',
        'instr_positions': {},
        'parent_filename': 'remote_contract.sol',
        'postiion_groups': {
            'remote_contract.sol:Puzzle': {
                'asm': {
                    '.code': [
                        {'begin': 25, 'end': 692, 'name': 'PUSH', 'value': '60'}, 
                        {'begin': 25, 'end': 692, 'name': 'PUSH', 'value': '40'}, 
                        {'begin': 25, 'end': 692, 'name': 'MSTORE'}, 
                        {'begin': 155, 'end': 288, 'name': 'CALLVALUE'},
                        {'begin': 155, 'end': 288, 'name': 'ISZERO'}, 
                        {'begin': 155, 'end': 288, 'name': 'PUSH [tag]', 'value': '1'}, 
                        {'begin': 155, 'end': 288, 'name': 'JUMPI'}, 
                        {'begin': 155, 'end': 288, 'name': 'PUSH', 'value': '0'}, 
                        {'begin': 155, 'end': 288, 'name': 'DUP1'}, 
                        {'begin': 155, 'end': 288, 'name': 'REVERT'}, 
                        {'begin': 155, 'end': 288, 'name': 'tag', 'value': '1'}, 
                        {'begin': 155, 'end': 288, 'name': 'JUMPDEST'}, 
                        {'begin': 184, 'end': 194, 'name': 'CALLER'}, 
                        {'begin': 176, 'end': 181, 'name': 'PUSH', 'value': '0'}, 
                        ...
                    ], 
                    '.data': {
                        '0': {
                            '.auxdata':'a165627a7a723058205dd5ad1a2690fcdf9a613ca17640ae0744024a2f853eb587dfbfdf7659f275dd0029', 
                            '.code': [
                                {'begin': 25, 'end': 692, 'name': 'PUSH', 'value': '60'}, 
                                {'begin': 25, 'end': 692, 'name': 'PUSH', 'value': '40'}, 
                                {'begin': 25, 'end': 692, 'name': 'MSTORE'}, 
                                {'begin': 25, 'end': 692, 'name': 'PUSH', 'value': '4'}, 
                                {'begin': 25, 'end': 692, 'name': 'CALLDATASIZE'}, 
                                {'begin': 25, 'end': 692, 'name': 'LT'}, 
                                {'begin': 25, 'end': 692, 'name': 'PUSH [tag]', 'value': '1'}, 
                                {'begin': 25, 'end': 692, 'name': 'JUMPI'}, 
                                {'begin': 25, 'end': 692, 'name': 'PUSH', 'value': '0'}, 
                                {'begin': 25, 'end': 692, 'name': 'CALLDATALOAD'}, 
                                {'begin': 25, 'end': 692, 'name': 'PUSH', 'value': '100000000000000000000000000000000000000000000000000000000'}, 
                                {'begin': 25, 'end': 692, 'name': 'SWAP1'}, 
                                {'begin': 25, 'end': 692, 'name': 'DIV'}, 
                                {'begin': 25, 'end': 692, 'name': 'PUSH', 'value': 'FFFFFFFF'}, 
                                ...
                            ]
                        }
                    }
                }
            }
        },
        'positions': [  // 与上面一样
            {'begin': 25, 'end': 692, 'name': 'PUSH', 'value': '60'}, 
            {'begin': 25, 'end': 692, 'name': 'PUSH', 'value': '40'}, 
            {'begin': 25, 'end': 692, 'name': 'MSTORE'}, 
            {'begin': 25, 'end': 692, 'name': 'PUSH', 'value': '4'}, 
            {'begin': 25, 'end': 692, 'name': 'CALLDATASIZE'}, 
            {'begin': 25, 'end': 692, 'name': 'LT'}, 
            {'begin': 25, 'end': 692, 'name': 'PUSH [tag]', 'value': '1'}, 
            {'begin': 25, 'end': 692, 'name': 'JUMPI'}, 
            {'begin': 25, 'end': 692, 'name': 'PUSH', 'value': '0'}, 
            {'begin': 25, 'end': 692, 'name': 'CALLDATALOAD'}, 
            {'begin': 25, 'end': 692, 'name': 'PUSH', 'value': '100000000000000000000000000000000000000000000000000000000'}, 
            {'begin': 25, 'end': 692, 'name': 'SWAP1'}, 
            {'begin': 25, 'end': 692, 'name': 'DIV'}, 
            {'begin': 25, 'end': 692, 'name': 'PUSH', 'value': 'FFFFFFFF'}, 
            ...
        ],
        'remap': '',
        'root_path': '',
        sig_to_func: {'a0d7afb7': 'diff()', 'cf309012': 'locked()', '8da5cb5b': 'owner()', '228cb733': 'reward()', '4fb60251': 'solution()'},
        'source': {
            'content': 'pragma solidity ^0.4.10;\ncontract Puzzle{\n\taddress public owner;\n\tbool public locked;\n\tuint public reward;\n\tbytes32 public diff;\n\tbytes public solution;\n\n\tfunction Puzzle(){\n\t\towner = msg.sender;\n\t\treward = msg.value;\n\t\tlocked = false;\n\t\tdiff = bytes32(11111); //pre-defined difficulty\n\t}\n\n\tfunction(){ //main code, runs at every invocation\t\n\t\tif (msg.sender == owner){ //update reward\t\t\n\t\t\tif (locked)\n\t\t\t\tthrow;\n\t\t\towner.send(reward);\n\t\t\treward = msg.value;\n\t\t}\n\t\telse\n\t\t\tif (msg.data.length > 0){ //submit a solution\t\t\t\n\t\t\t\tif (locked) throw;\n\t\t\t\tif (sha256(msg.data) < diff){\n\t\t\t\t\tmsg.sender.send(reward); //send reward\n\t\t\t\t\tsolution = msg.data;\n\t\t\t\t\tlocked = true;\n\t\t\t\t}\n\t\t\t\t}\n\t\t\t\t}\n\t\t\t}'
            'filename': 'remote_contract.sol',
            'line_break_positions': [24, 41, 64, 85, 106, 128, 152, 153, 173, 195, 217, 235, 285, 288, ...]
        },
        'sources': {
            'remote_contract.sol': {
            'content': 'pragma solidity ^0.4.10;\ncontract Puzzle{\n\taddress public owner;\n\tbool public locked;\n\tuint public reward;\n\tbytes32 public diff;\n\tbytes public solution;\n\n\tfunction Puzzle(){\n\t\towner = msg.sender;\n\t\treward = msg.value;\n\t\tlocked = false;\n\t\tdiff = bytes32(11111); //pre-defined difficulty\n\t}\n\n\tfunction(){ //main code, runs at every invocation\t\n\t\tif (msg.sender == owner){ //update reward\t\t\n\t\t\tif (locked)\n\t\t\t\tthrow;\n\t\t\towner.send(reward);\n\t\t\treward = msg.value;\n\t\t}\n\t\telse\n\t\t\tif (msg.data.length > 0){ //submit a solution\t\t\t\n\t\t\t\tif (locked) throw;\n\t\t\t\tif (sha256(msg.data) < diff){\n\t\t\t\t\tmsg.sender.send(reward); //send reward\n\t\t\t\t\tsolution = msg.data;\n\t\t\t\t\tlocked = true;\n\t\t\t\t}\n\t\t\t\t}\n\t\t\t\t}\n\t\t\t}'
            'filename': 'remote_contract.sol',
            'line_break_positions': [24, 41, 64, 85, 106, 128, 152, 153, 173, 195, 217, 235, 285, 288, ...]
            }
        },
        'var_names': ['owner', 'locked', 'reward', 'diff', 'solution']
    }
    ```

    ast_helper
    ```
    allow_path: '',
    contracts: {
        'contractsById': {95: {'attributes': {...}, 'children': [...], 'id': 95, 'name': 'ContractDefinition', 'src': '25:667:0'}}, 
        'contractsByName': {'remote_contract.sol:Puzzle': {'attributes': {...}, 'children': [...], 'id': 95, 'name': 'ContractDefinition', 'src': '25:667:0'}}, 
        'sourcesByContract': {95: 'remote_contract.sol'}
    },
    input_type: 'solidity',
    remap: '',
    source_list: {
        'remote_contract.sol': {
            'AST': {
                'attributes': {
                    'absolutePath': 'remote_contract.sol', 
                    'exportedSymbols': {'Puzzle': [95]}
                }, 
                'children': [
                    {
                        'attributes': {...}, 'id': 1, 'name': 'PragmaDirective', 'src': '0:24:0'
                    }, 
                    {
                        'attributes': {...}, 'children': [...], 'id': 95, 'name': 'ContractDefinition', 'src': '25:667:0'
                    }
                ], 
                'id': 96, 'name': 'SourceUnit', 'src': '0:692:0'
            }
        }
    }
    ```
    
    2. results, exit_code = run_solidity_analysis(inputs)
    



======

An Analysis Tool for Smart Contracts

[![Gitter][gitter-badge]][gitter-url]
[![License: GPL v3][license-badge]][license-badge-url]
[![Build Status](https://travis-ci.org/melonproject/oyente.svg?branch=master)](https://travis-ci.org/melonproject/oyente)

*This repository is currently maintained by Xiao Liang Yu ([@yxliang01](https://github.com/yxliang01)). If you encounter any bugs or usage issues, please feel free to create an issue on [our issue tracker](https://github.com/melonproject/oyente/issues).*

## Quick Start

A container with required dependencies configured can be found [here](https://hub.docker.com/r/luongnguyen/oyente/). The image is however outdated. We are working on pushing the latest image to dockerhub for your convenience. If you experience any issue with this image, please try to build a new docker image by pulling this codebase before open an issue.

To open the container, install docker and run:

```
docker pull luongnguyen/oyente && docker run -i -t luongnguyen/oyente
```

To evaluate the greeter contract inside the container, run:

```
cd /oyente/oyente && python oyente.py -s greeter.sol
```

and you are done!

Note - If need the [version of Oyente](https://github.com/melonproject/oyente/tree/290f1ae1bbb295b8e61cbf0eed93dbde6f287e69) referred to in the paper, run the container from [here](https://hub.docker.com/r/hrishioa/oyente/)

To run the web interface, execute
`docker run -w /oyente/web -p 3000:3000 oyente:latest ./bin/rails server`

## Custom Docker image build

```
docker build -t oyente .
docker run -it -p 3000:3000 -e "OYENTE=/oyente/oyente" oyente:latest
```

Open a web browser to `http://localhost:3000` for the graphical interface.

## Installation

Execute a python virtualenv

```
python -m virtualenv env
source env/bin/activate
```

Install Oyente via pip:

```
$ pip2 install oyente
```
Dependencies:

The following require a Linux system to fufill. macOS instructions forthcoming.

[solc](https://github.com/melonproject/oyente#solc)
[evm](https://github.com/melonproject/oyente#evm-from-go-ethereum)

## Full installation

### Install the following dependencies
#### solc
```
$ sudo add-apt-repository ppa:ethereum/ethereum
$ sudo apt-get update
$ sudo apt-get install solc
```

#### evm from [go-ethereum](https://github.com/ethereum/go-ethereum)

1. https://geth.ethereum.org/downloads/ or
2. By from PPA if your using Ubuntu
```
$ sudo apt-get install software-properties-common
$ sudo add-apt-repository -y ppa:ethereum/ethereum
$ sudo apt-get update
$ sudo apt-get install ethereum
```

#### [z3](https://github.com/Z3Prover/z3/releases) Theorem Prover version 4.5.0.

Download the [source code of version z3-4.5.0](https://github.com/Z3Prover/z3/releases/tag/z3-4.5.0)

Install z3 using Python bindings

```
$ python scripts/mk_make.py --python
$ cd build
$ make
$ sudo make install
```

#### [Requests](https://github.com/kennethreitz/requests/) library

```
pip install requests
```

#### [web3](https://github.com/pipermerriam/web3.py) library

```
pip install web3
```

### Evaluating Ethereum Contracts

```
#evaluate a local solidity contract
python oyente.py -s <contract filename>

#evaluate a local solidity with option -a to verify assertions in the contract
python oyente.py -a -s <contract filename>

#evaluate a local evm contract
python oyente.py -s <contract filename> -b

#evaluate a remote contract
python oyente.py -ru https://gist.githubusercontent.com/loiluu/d0eb34d473e421df12b38c12a7423a61/raw/2415b3fb782f5d286777e0bcebc57812ce3786da/puzzle.sol

```

And that's it! Run ```python oyente.py --help``` for a list of options.

## Paper

The accompanying paper explaining the bugs detected by the tool can be found [here](https://www.comp.nus.edu.sg/~prateeks/papers/Oyente.pdf).

## Miscellaneous Utilities

A collection of the utilities that were developed for the paper are in `misc_utils`. Use them at your own risk - they have mostly been disposable.

1. `generate-graphs.py` - Contains a number of functions to get statistics from contracts.
2. `get_source.py` - The *get_contract_code* function can be used to retrieve contract source from [EtherScan](https://etherscan.io)
3. `transaction_scrape.py` - Contains functions to retrieve up-to-date transaction information for a particular contract.

## Benchmarks

Note: This is an improved version of the tool used for the paper. Benchmarks are not for direct comparison.

To run the benchmarks, it is best to use the docker container as it includes the blockchain snapshot necessary.
In the container, run `batch_run.py` after activating the virtualenv. Results are in `results.json` once the benchmark completes.

The benchmarks take a long time and a *lot* of RAM in any but the largest of clusters, beware.

Some analytics regarding the number of contracts tested, number of contracts analysed etc. is collected when running this benchmark.

## Contributing

Checkout out our [contribution guide](https://github.com/melonproject/oyente/blob/master/CONTRIBUTING.md) and the code structure [here](https://github.com/melonproject/oyente/blob/master/code.md).


[gitter-badge]: https://img.shields.io/gitter/room/melonproject/oyente.js.svg?style=flat-square
[gitter-url]: https://gitter.im/melonproject/oyente?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge
[license-badge]: https://img.shields.io/badge/License-GPL%20v3-blue.svg?style=flat-square
[license-badge-url]: ./LICENSE
