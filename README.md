Oyente
======

## Notice
1. solc version `v0.4.19`

1. evm version `v1.7.3`/`v1.8.2-v1.8.16` `v1.8.17+`evm disasm has changed which appears to cause issues with the tokenizer, 在change_format()中对十六进制进行处理为十进制可能会解决问题

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
1. 调用`analyze_solidity()`
    1. inputs = InputHelper(...).get_inputs(...) 生成.evm和.evm.disasm文件，获取合约信息用于分析

    inputs
    ```
    [
        {
            'contract': '/home/daniel/paper/oyente/remote_contract.sol:Puzzle', 
            'source_map': SourceMap对象, 
            'source': 'remote_contract.sol', 
            'c_source': '/home/daniel/paper/oyente/remote_contract.sol', 
            'c_name': 'Puzzle', 
            'disasm_file': '/home/daniel/paper/oyente/remote_contract.sol:Puzzle.evm.disasm'
        }
    ]
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

    ```python
    # oyente.py
    results, exit_code = run_solidity_analysis(inputs)
        # symExec.py 符号执行
        result, return_code = symExec.run(...)
            analyze()   # 分析
                run_build_cfg_and_analyze()
                    build_cfg_and_analyze() # 构建控制流图和分析，有超时检测
                        change_format()
                            # 读取disasm文件，替换部分操作指令，去除pc中的前导0，添加=>得到新的disasm文件
                            # 高版本的evm可能需要在这里处理十六进制的pc，转为十进制，否则会报错(如：c JUMPI 中无效的c)
                        # 读取disasm文件
                        disasm_file.readline()  # 忽略第一行字节码
                        tokens = tokenize.generate_tokens(disasm_file.readline)
                        collect_vertices(tokens)    # 1.解析disasm文件 2.识别每个基本块（开始/结束pc位置和跳转类型） 3.将它们存储在顶点中
                            instructions[]  # 所有指令数组{0: 'PUSH1 0x60 ', 2: 'PUSH1 0x40 ', 4: 'MSTORE ', 5: 'PUSH1 0x04 '}
                            end_ins_dict    # 存储基本块的开始结束pc{0: 12, 13: 64, 65: 75, 76: 86, 87: 97, 98: 108 ...}
                            jump_type   # 存储每个块的跳转类型{key:块起始pc, value:类型} { 0:'conditional', 13:'conditional', 65:'conditional', 76:'conditional', 87:'conditional', 98:'conditional', 109:'conditional', 116:'terminal', 120:'conditional', 206:'conditional', 227:'terminal', 231:'unconditional', 332:'conditional', ... , 1302:'unconditional', 1305:'terminal', 519:'falls_to', 548:'falls_to', 549:'falls_to', 612:'falls_to', 696:'falls_to', 1027:'falls_to', 1061:'falls_to', 1220:'falls_to', 1250:'falls_to', 1268:'falls_to'} falls_to都在后面，会影响边的构建
                        construct_bb()  # 构建BasicBlock字典列表，未设置jump_target
                            vertices    # {0: <BasicBlock>, 13: <BasicBlock>, 65: <BasicBlock>,  ...}
                            # {0: {start: 0, end: 12, type: 'conditional', jump_target: 0, instructions: ['PUSH1 0x60 ', 'PUSH1 0x40 ', 'MSTORE ', 'PUSH1 0x04 ', 'CALLDATASIZE ', 'LT ', 'PUSH2 0x006d ', 'JUMPI ']}, ... }
                            edges   # 此时赋值为[], {0: [], 13: [], 65: [], ...}
                        construct_static_edges()    # 构造静态边，设置BasicBlock的falls_to属性
                            add_falls_to()  # 1.设置vertices BasicBlock中的falls_to属性值，2.构造edges 这些边是静态的，BasicBlock中有falls_to(落在)属性
                                edges   # {0: [13], 13: [65], 65: [76], 76: [87], 87: [98], 98: [109], 109: [116], 116: [], 120: [206], ...} pc经过排序
                                        # 简单的设置为下一个块的起始pc(why?)
                                vertices    # {0: {start: 0, end: 12, falls_to: 13, type: 'conditional', jump_target: 0, instructions: ['PUSH1 0x60 ', 'PUSH1 0x40 ', 'MSTORE ', 'PUSH1 0x04 ', 'CALLDATASIZE ', 'LT ', 'PUSH2 0x006d ', 'JUMPI ']},  ...}
                                            # 简单的设置falls_to为下一个块的起始pc(why?)
                                            # jump_target、branch_expression(JUMPI时)在指令执行的时候赋值
                        full_sym_exec()  # 符号执行：跳转目标是动态构建的，构造global_state和path_conditions_and_vars用于符号执行
                            # executing, starting from beginning 执行，从头开始
                            path_conditions_and_vars = {"path_condition" : []}  # 路径条件和变量
                            global_state = get_init_global_state(path_conditions_and_vars)  # 初始化全局状态，同时对路径条件和变量赋值
                                # global_state: {'balance': {'Is': init_Is - Iv, 'Ia': init_Ia + Iv}, 'pc': 0, 'Ia': {}, 'miu_i': 0, 'value': Iv, 'sender_address': Is, 'receiver_address': Ia, 'gas_price': Ip, 'origin': Io, 'currentCoinbase': IH_c, 'currentTimestamp': IH_s, 'currentNumber': IH_i, 'currentDifficulty': IH_d, 'currentGasLimit': IH_l}
                                # 都是BitVec对象 { ast: <Ast object>, ctx: <z3.z3.Context object>}
                                # path_conditions_and_vars: {'path_condition': [0 <= Iv, init_Is >= Iv, 0 <= init_Ia], 'Is': Is, 'Ia': Ia, 'Iv': Iv, 'Ip': Ip, 'Io': Io, 'IH_c': IH_c, 'IH_i': IH_i, 'IH_d': IH_d, 'IH_l': IH_l, 'IH_s': IH_s}
                                # 都是BitVec对象 { ast: <Ast object>, ctx: <z3.z3.Context object>}
                            analysis = init_analysis()
                                # analysis: {'gas': 0, 'gas_mem': 0, 'money_flow': [('Is', 'Ia', 'Iv')] (source, destination, amount), 'reentrancy_bug': [], 'money_concurrency_bug': [], 'time_dependency_bug': {}}
                            params = Parameter(path_conditions_and_vars=path_conditions_and_vars, global_state=global_state, analysis=analysis)
                            if g_src_map:
                                start_block_to_func_sig = get_start_block_to_func_sig() # 获取函数的pc和签名 {552: '228cb733', 593: '4fb60251', 735: '8da5cb5b', 820: 'a0d7afb7', 869: 'cf309012'}
                                    # PUSH4 0x228cb733  (函数签名)
                                    # EQ
                                    # PUSH2 0x0228    (pc)
                                    # JUMPI
                                    # DUP1
                                    # PUSH4 0x4fb60251
                                    # EQ
                                    # PUSH2 0x0251    (pc)
                                    # JUMPI
                                    # DUP1
                                    # PUSH4 0x8da5cb5b
                                    # EQ
                                    # PUSH2 0x02df    (pc)
                                    # JUMPI
                                    # DUP1
                                    # PUSH4 0xa0d7afb7
                                    # EQ
                                    # PUSH2 0x0334    (pc)
                                    
                            return sym_exec_block(params, 0, 0, 0, -1, 'fallback')  # 从起始地址符号执行一个块，内含递归符号执行 
                            sym_exec_block(params, block, pre_block, depth, func_call, current_func_name)
                                global solver
                                global visited_edges
                                global money_flow_all_paths
                                global path_conditions
                                global global_problematic_pcs
                                global all_gs
                                global results
                                global g_src_map

                                visited = params.visited
                                stack = params.stack
                                mem = params.mem
                                memory = params.memory
                                global_state = params.global_state
                                sha3_list = params.sha3_list
                                path_conditions_and_vars = params.path_conditions_and_vars
                                analysis = params.analysis
                                calls = params.calls
                                overflow_pcs = params.overflow_pcs
                                # 若当前块是函数，则给current_func_name赋值
                                # 创建Edge(pre_block, cur_block)更新visited_edges是否+1
                                # 检测边访问次数是否超过限制
                                # 检测gas使用是否超过限制
                                # 获取块指令并循环执行
                                    sym_exec_ins(params, block, instr, func_call, current_func_name)
                                        global MSIZE
                                        global visited_pcs  # 已访问的pc
                                        global solver
                                        global vertices
                                        global edges
                                        global g_src_map
                                        global calls_affect_state
                                        global data_source

                                        stack = params.stack
                                        mem = params.mem
                                        memory = params.memory
                                        global_state = params.global_state
                                        sha3_list = params.sha3_list
                                        path_conditions_and_vars = params.path_conditions_and_vars
                                        analysis = params.analysis
                                        calls = params.calls
                                        overflow_pcs = params.overflow_pcs
                                        # 添加visited_pcs
                                        # 获取操作码
                                        # 如果是INVALID/ASSERTFAIL操作码则进行处理

                                        # 符号执行之前收集分析结果，符号执行将修改stack和mem
                                        update_analysis(analysis, opcode, stack, mem, global_state, path_conditions_and_vars, solver)
                                            # gas/gas_mem计算更新
                                            # 如果是CALL并且recipient是符号，则检测重入，添加分析结果，添加money信息
                                                reentrancy_result = check_reentrancy_bug(path_conditions_and_vars, stack, global_state)
                                                analysis["reentrancy_bug"].append(reentrancy_result)

                                                analysis["money_concurrency_bug"].append(global_state["pc"])
                                                analysis["money_flow"].append( ("Ia", str(recipient), str(transfer_amount)))

                                            # 如果是SUCIDE，添加money信息
                                                analysis['money_concurrency_bug'].append(global_state['pc'])
                                                analysis["money_flow"].append(("Ia", str(recipient), "all_remaining"))

                                        # 如果确认存在重入则将pc添加到global_problematic_pcs["reentrancy_bug"]

                                        # 符号执行指令......(STOP和算术运算、比较和按位逻辑运算、SHA3、环境信息、区块信息、Stack, Memory, Storage, 和 Flow信息、PUSH、DUP、SWAP、LOG、系统操作)
                                        # EXP: 若两个数都为整数则计算，否则压入未知符号值代替(不能计算)
                                        # SHA3: (若两个数都为整数 and sha3_list[position]没有) or 不都为整数 则压入符号值，不都为整数时将符号值变量添加到path_conditions_and_vars中
                                        # BALANCE: address不是整数时，压入符号变量，加入到path_conditions_and_vars中
                                        # CALL/CALLCODE: 1.将pc添加到calls 2.遍历calls(call_pc) 3.如果call_pc不在calls_affect_state中,则calls_affect_state[call_pc] = False
                                        # SSTORE: 遍历calls(call_pc),令calls_affect_state[call_pc] = True
                                        # ...

                                # visited将block标记为一访问
                                # depth + 1

                                # 块指令执行玩后(有块的指令分析结果)，添加重入分析、money分析和时间戳依赖分析结果到全局变量中

                                # 跳转到下一个block(递归)


            ret = detect_vulnerabilities()
                detect_integer_underflow()
                    # global_problematic_pcs['integer_underflow']/pcs在SUB指令执行时处理
                    integer_underflow = IntegerUnderflow(g_src_map, global_problematic_pcs['integer_underflow'])
                        # 删除假阳性pc(1.删除没有源代码的pc 2.删除有相同pos的pc pos如："{'begin': 417, 'end': 435, 'name': 'CALL'}")
                        # 通过新pcs获取源代码输出警告
                detect_integer_overflow()
                    # global_problematic_pcs['integer_overflow']/pcs在ADD指令执行时处理
                    # 另外删除在revertible_overflow_pcs中的pc，revert会回滚，为什么integer_underflow中不处理？
                    integer_overflow = IntegerOverflow(g_src_map, overflows)
                        # 同上
                detect_parity_multisig_bug_2()
                detect_callstack_attack()   # 调用未判断ISZERO
                    # 读取.disasm文件处理得到指令ins[000: ('0', 'PUSH', '1', '60')...]
                    pcs = check_callstack_attack(instr) # 检测后面没有ISZERO的pcs
                    callstack = CallStack(g_src_map, pcs, calls_affect_state)
                        # 根据calls_affect_state删除假阳性的pc
                        # 通过新pcs获取源代码输出警告
                detect_money_concurrency()  # 检测交易顺序依赖(TOD)
                    # 两层对比遍历money_flow_all_paths，检查两个不同的轨迹是否具有不同的以太流量
                detect_time_dependency()
                detect_reentrancy()
                detect_assertion_failure()
            closing_message()
            return ret
    ```

    results
    ```
    {
        '/home/daniel/paper/oyente/remote_contract.sol': {
            'Puzzle': {
                'evm_code_coverage': '85.1', 
                'vulnerabilities': {
                    'integer_underflow': [
                        'remote_contract.sol:2:1: Warning: Integer Underflow.\ncontract Puzzle{\n^\nSpanning multiple lines.\nInteger Underflow occurs if:\n    reward = 58350110510813448903360825092523159431151750792099371751192934472640320503809\n    owner = 0\n    diff = 1', 'remote_contract.sol:7:2: Warning: Integer Underflow.\n\tbytes public solution'
                    ], 
                    'integer_overflow': [
                        'remote_contract.sol:7:2: Warning: Integer Overflow.\n\tbytes public solution'
                    ], 
                    'callstack': [
                        'remote_contract.sol:20:4: Warning: Callstack Depth Attack Vulnerability.\n\t\t\towner.send(reward)'
                    ], 
                    'money_concurrency': [
                        [
                            'remote_contract.sol:27:6: Warning: Transaction-Ordering Dependency.\n\t\t\t\t\tmsg.sender.send(reward)'], ['remote_contract.sol:20:4: Warning: Transaction-Ordering Dependency.\n\t\t\towner.send(reward)'
                        ]
                    ], 
                    'time_dependency': [], 
                    'reentrancy': [] 
                    'assertion_failure': [], 
                    'parity_multisig_bug_2': []
                }
            }
        }
    }
    ```

    exit_code
    ```
    exit_code = 1
    ```



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
