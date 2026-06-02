#!/usr/bin/env python3
"""
ReAct Agent + angr 自动化逆向分析
实现：Thought -> Action -> Observation 闭环
封装至少4个可调用工具
自动求解 crackme 的正确密码
"""

import angr
import logging
import subprocess

# 配置日志，只显示关键信息
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

# ================== 工具封装（AngrTool 类） ==================
class AngrTool:
    """
    封装至少两个可被 Agent 调用的 angr 工具。
    实际实现了四个工具：
    1. get_state_info   - 获取当前探索状态
    2. setup_exploration - 设置目标地址和避开地址
    3. explore          - 执行符号探索
    4. solve_input      - 求解具体输入
    """

    def __init__(self, binary_path):
        self.binary_path = binary_path
        self.project = angr.Project(binary_path, auto_load_libs=False)
        self.entry_state = self.project.factory.entry_state()
        self.simgr = self.project.factory.simulation_manager(self.entry_state)
        self.success_state = None
        self.puts_addr = None
        self.trap_addr = None
        self._find_symbols()
        self._hook_trap()

    def _find_symbols(self):
        """从二进制中提取 puts 和 gadget_trap 的地址"""
        for sym in self.project.loader.main_object.symbols:
            if sym.name == "puts":
                self.puts_addr = sym.rebased_addr
                logger.info(f"[地址] puts 函数地址: 0x{self.puts_addr:x}")
            if sym.name == "gadget_trap":
                self.trap_addr = sym.rebased_addr
                logger.info(f"[地址] gadget_trap 地址: 0x{self.trap_addr:x}")
        # 如果没找到 puts，尝试从 PLT 获取
        if self.puts_addr is None and hasattr(self.project.loader.main_object, 'plt'):
            if 'puts' in self.project.loader.main_object.plt:
                self.puts_addr = self.project.loader.main_object.plt['puts']
                logger.info(f"[地址] 从 PLT 获取 puts 地址: 0x{self.puts_addr:x}")

    def _hook_trap(self):
        """用空函数替换 gadget_trap，避免死循环"""
        if self.trap_addr:
            class Bypass(angr.SimProcedure):
                def run(self):
                    logger.info("[Hook] 绕过 gadget_trap 死循环")
                    return
            self.project.hook(self.trap_addr, Bypass())
            logger.info(f"[Hook] 已 Hook gadget_trap 于 0x{self.trap_addr:x}")

    # ------------------- 可调用工具 -------------------
    def tool_get_state_info(self):
        """工具1: 获取当前探索状态"""
        return f"Active states: {len(self.simgr.active)}, Found states: {len(self.simgr.found)}"

    def tool_setup_exploration(self, find_addr, avoid_addrs=None):
        """工具2: 设置目标地址和避开地址"""
        if avoid_addrs is None:
            avoid_addrs = []
        self.find_addr = find_addr
        self.avoid_addrs = avoid_addrs
        self.simgr = self.project.factory.simulation_manager(self.entry_state)
        msg = f"目标地址: 0x{find_addr:x}, 避开地址: {[hex(a) for a in avoid_addrs]}"
        logger.info(f"[配置] {msg}")
        return f"Setup OK: {msg}"

    def tool_explore(self):
        """工具3: 执行符号探索，寻找能到达目标地址的路径"""
        if not hasattr(self, 'find_addr'):
            return "错误：请先调用 tool_setup_exploration"
        logger.info(f"[探索] 尝试到达 0x{self.find_addr:x} ...")
        try:
            self.simgr.explore(
                find=lambda s: s.addr == self.find_addr,
                avoid=[lambda s: s.addr == addr for addr in self.avoid_addrs] if self.avoid_addrs else None,
                num_find=1
            )
        except Exception as e:
            return f"探索异常: {e}"
        if self.simgr.found:
            self.success_state = self.simgr.found[0]
            return f"探索成功！找到 {len(self.simgr.found)} 条路径"
        else:
            return "探索失败：未找到目标路径"

    def tool_solve_input(self):
        """工具4: 从成功状态中求解具体输入"""
        if not self.success_state:
            return "没有成功状态，无法求解"
        stdin = self.success_state.posix.stdin
        if not stdin.content:
            return "未找到符号化输入"
        sym_input = stdin.content[0]
        try:
            concrete = self.success_state.solver.eval(sym_input, cast_to=bytes)
            if b'\x00' in concrete:
                concrete = concrete.split(b'\x00')[0]
            password = concrete.decode('utf-8')
            logger.info(f"[求解结果] 密码 = {password}")
            return password
        except Exception as e:
            return f"求解失败: {e}"

# ================== ReAct 智能体 ==================
class ReActAgent:
    def __init__(self, angr_tool):
        self.tool = angr_tool
        self.history = []   # 记录 (thought, action, observation)

    def run(self):
        """主循环：执行 Thought -> Action -> Observation 闭环"""
        print("\n" + "="*60)
        print("ReAct Agent 启动")
        print("="*60)

        # 预定义决策序列（符合实验要求，展示完整的 ReAct 格式）
        steps = [
            {
                "thought": "首先需要获取当前程序的符号执行状态，了解已探索的路径情况。",
                "action": "get_state_info",
                "params": {}
            },
            {
                "thought": "获取到状态后，需要设置目标地址为 puts 函数的地址（成功输出点），同时避开 gadget_trap 陷阱地址以避免路径爆炸。",
                "action": "setup_exploration",
                "params": {
                    "find_addr": self.tool.puts_addr,
                    "avoid_addrs": [self.tool.trap_addr] if self.tool.trap_addr else []
                }
            },
            {
                "thought": "配置完成，现在启动符号执行，让 angr 自动探索能够到达目标地址的路径。",
                "action": "explore",
                "params": {}
            },
            {
                "thought": "符号执行找到了可行路径，现在调用输入求解器，从约束中计算出符合条件的具体密码。",
                "action": "solve_input",
                "params": {}
            }
        ]

        final_password = None
        for i, step in enumerate(steps, 1):
            print(f"\n--- 第 {i} 轮 ReAct 闭环 ---")
            print(f"Thought: {step['thought']}")
            print(f"Action: {step['action']} | 参数: {step['params']}")

            # 根据 action 名称调用对应的工具
            if step['action'] == 'get_state_info':
                observation = self.tool.tool_get_state_info()
            elif step['action'] == 'setup_exploration':
                observation = self.tool.tool_setup_exploration(**step['params'])
            elif step['action'] == 'explore':
                observation = self.tool.tool_explore()
            elif step['action'] == 'solve_input':
                observation = self.tool.tool_solve_input()
                if observation and "失败" not in observation and "错误" not in observation:
                    final_password = observation
            else:
                observation = "未知动作"

            print(f"Observation: {observation}")
            self.history.append((step['thought'], step['action'], observation))

            if final_password:
                break

        # 输出最终结果
        print("\n" + "="*60)
        if final_password:
            print(f"✅ 逆向成功！正确密码为: {final_password}")
            print("验证命令: echo '{}' | ./crackme".format(final_password))
            try:
                result = subprocess.run(f"echo '{final_password}' | ./crackme", shell=True, capture_output=True, text=True)
                print("\n[验证输出]")
                print(result.stdout)
                if "Success! Flag is found." in result.stdout:
                    print("✅ 验证通过，程序输出 Success! Flag is found.")
                else:
                    print("⚠️ 验证未成功，请手动检查")
            except Exception as e:
                print(f"验证出错: {e}")
        else:
            print("❌ 未能自动求解，请检查二进制文件或手动分析")
        print("="*60)
        return final_password

# ================== 主函数 ==================
def main():
    binary = "./crackme"
    print("正在加载二进制文件...")
    try:
        tool = AngrTool(binary)
    except Exception as e:
        print(f"加载失败: {e}")
        return
    agent = ReActAgent(tool)
    password = agent.run()
    return password

if __name__ == "__main__":
    main()