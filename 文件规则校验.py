import re
import requests
import time
import shutil
from urllib.parse import urlparse
from pathlib import Path
from collections import defaultdict
from datetime import datetime

# 正则表达式模式
ruleset_pattern = re.compile(r'^ruleset=([^,]+),(.+)$')
proxy_group_pattern = re.compile(r'^custom_proxy_group=([^`]+)`([^`]+)`(.+)$')
select_node_pattern = re.compile(r'\[([^\]]*)\]')  # 匹配 [] 内的内容

# 检查 URL 有效性
def check_url_validity(url, line_num, name, send_request=False):
    parsed_url = urlparse(url)
    if not all([parsed_url.scheme, parsed_url.netloc]):
        return f"错误: 第 {line_num} 行 - 无效的 URL 格式: {url} (规则: {name})", False
    if send_request:
        try:
            response = requests.head(url, timeout=5, allow_redirects=True)
            if response.status_code == 200:
                final_url = response.url if response.url != url else "无重定向"
                return f"链接有效: {url} (规则: {name}) - 最终地址: {final_url}", True
            else:
                return f"链接无效: {url} (规则: {name})，状态码: {response.status_code}", False
        except requests.RequestException as e:
            return f"链接检查失败: {url} (规则: {name})，错误: {e}", False
    return f"URL 格式正确: {url} (规则: {name}) - 未发送网络请求", True

# 校验正则表达式
def validate_regex(pattern, line_num, name):
    try:
        re.compile(pattern)
        return f"正则表达式有效: {pattern} (策略组: {name})", True
    except re.error as e:
        return f"错误: 第 {line_num} 行 - 无效的正则表达式: {pattern} (策略组: {name})，错误: {e}", False

# 测试延迟
def test_latency(url, timeout=5):
    try:
        start = time.time()
        response = requests.get(url, timeout=timeout)
        if response.status_code == 204 or response.status_code == 200:
            latency = (time.time() - start) * 1000  # 转换为毫秒
            return f"延迟测试成功: {url} - {latency:.2f}ms", True
        else:
            return f"延迟测试失败: {url} - 状态码: {response.status_code}", False
    except requests.RequestException as e:
        return f"延迟测试失败: {url} - 错误: {e}", False

# 校验策略组类型和参数
def validate_proxy_group_type(type_, nodes, line_num, name):
    valid_types = ['select', 'url-test', 'fallback', 'load-balance']
    if type_ not in valid_types:
        return f"错误: 第 {line_num} 行 - 无效的策略组类型: {type_} (策略组: {name})", False
    if type_ in ['url-test', 'fallback', 'load-balance']:
        parts = nodes.split('`')
        if len(parts) < 3 or not parts[1].startswith('http'):
            return f"错误: 第 {line_num} 行 - {type_} 类型缺少有效 URL 或参数: {nodes} (策略组: {name})", False
    return None, True

# 校验配置文件
def validate_config(config_content, send_request=False, test_latency_flag=False, latency_timeout=5):
    rulesets = {}
    proxy_groups = {}
    proxy_group_names = set()  # 存储所有 custom_proxy_group 的名称
    lines = config_content.splitlines()
    report = defaultdict(list)
    in_custom_section = False

    # 第一遍：收集所有 custom_proxy_group 名称
    for line in lines:
        line = line.strip()
        if not line or line.startswith(';'):
            continue
        proxy_group_match = proxy_group_pattern.match(line)
        if proxy_group_match:
            name = proxy_group_match.group(1)
            proxy_group_names.add(name)

    # 第二遍：校验配置内容
    for i, line in enumerate(lines, 1):
        line = line.strip()
        if not line or line.startswith(';'):
            continue

        # 识别 [custom] 节
        if line == '[custom]':
            in_custom_section = True
            continue
        if line.startswith('[') and line != '[custom]':
            in_custom_section = False
            report["errors"].append(f"错误: 第 {i} 行 - 不支持的节标题: {line}")
            continue

        # 跳过固定配置项的语法检查
        if in_custom_section and line in ['enable_rule_generator=true', 'overwrite_original_rules=true']:
            continue

        # 校验 ruleset
        ruleset_match = ruleset_pattern.match(line)
        if ruleset_match:
            name, value = ruleset_match.groups()
            if name in rulesets:
                report["warnings"].append(f"警告: 第 {i} 行 - 重复的 ruleset 定义: {name}")
            rulesets[name] = value
            if value.startswith('http') or value.startswith('clash-classic:http'):
                msg, valid = check_url_validity(value.split('clash-classic:')[-1], i, name, send_request)
                report["url_checks"].append(msg)
                if not valid:
                    report["errors"].append(msg)
            elif not value.startswith('['):
                report["errors"].append(f"错误: 第 {i} 行 - ruleset 值不符合预期格式: {value} (规则: {name})")
            # 检查 ruleset 名称是否在 custom_proxy_group 中
            if name not in proxy_group_names:
                report["warnings"].append(f"警告: 第 {i} 行 - ruleset '{name}' 未在 custom_proxy_group 中定义")
            continue

        # 校验 custom_proxy_group
        proxy_group_match = proxy_group_pattern.match(line)
        if proxy_group_match:
            name, type_, nodes = proxy_group_match.groups()
            if name in proxy_groups:
                report["warnings"].append(f"警告: 第 {i} 行 - 重复的 custom_proxy_group 定义: {name}")
            proxy_groups[name] = (type_, nodes)

            # 检查策略组类型
            type_msg, type_valid = validate_proxy_group_type(type_, nodes, i, name)
            if not type_valid:
                report["errors"].append(type_msg)

            # 检查 select 类型后面的规则名称
            if type_ == 'select':
                if not nodes.startswith('['):  # 如果是正则表达式
                    msg, valid = validate_regex(nodes, i, name)
                    report["regex_checks"].append(msg)
                    if not valid:
                        report["errors"].append(msg)
                else:  # 如果是节点列表
                    node_list = select_node_pattern.findall(nodes)
                    builtin_rules = {'DIRECT', 'REJECT'}
                    for node in node_list:
                        if node and node not in proxy_group_names and node not in builtin_rules:
                            report["warnings"].append(f"警告: 第 {i} 行 - 策略组 '{name}' 中的规则 '[ {node} ]' 未在 custom_proxy_group 中定义")

            # 检查正则表达式（非 select 类型）
            elif type_ in ['url-test', 'fallback', 'load-balance'] and nodes.startswith('(?='):
                parts = nodes.split('`')
                if len(parts) > 0:
                    msg, valid = validate_regex(parts[0], i, name)
                    report["regex_checks"].append(msg)
                    if not valid:
                        report["errors"].append(msg)

            # 测试延迟（仅对 url-test 和 fallback）
            if test_latency_flag and type_ in ['url-test', 'fallback']:
                url = nodes.split('`')[1] if '`' in nodes else None
                if url and url.startswith('http'):
                    msg, _ = test_latency(url, latency_timeout)
                    report["latency_tests"].append(msg)
            continue

        # 未识别的行视为语法错误
        if not in_custom_section:
            report["errors"].append(f"错误: 第 {i} 行 - 语法错误: {line}")

    return report

# 输出校验报告并询问是否保存
def print_and_log_report(report, filename):
    print(f"\n=== Clash 配置文件校验报告 ({filename}) ===")
    has_issues = False

    # 只输出错误和警告到终端
    for section in ["errors", "warnings"]:
        items = report.get(section, [])
        if items:
            has_issues = True
            title = "错误（需要修复）" if section == "errors" else "警告（建议检查）"
            print(f"\n{title}：")
            for item in items:
                print(f"- {item}")

    if not has_issues:
        print("\n无错误或警告")

    print("\n校验完成！")

    # 询问是否保存报告
    while True:
        save_choice = input("是否保存校验报告到文件？(y/n，默认 n)：").lower() or 'n'
        if save_choice in ['y', 'n']:
            if save_choice == 'y':
                log_file = f"clash_validation_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                with open(log_file, 'w', encoding='utf-8') as f:
                    f.write(f"=== Clash 配置文件校验报告 ({filename}) ===\n")
                    for section, items in report.items():
                        if not items:
                            continue
                        title = {
                            "errors": "错误（需要修复）",
                            "warnings": "警告（建议检查）",
                            "url_checks": "URL 检查结果",
                            "regex_checks": "正则表达式检查结果",
                            "latency_tests": "延迟测试结果"
                        }.get(section, section)
                        f.write(f"\n{title}：\n")
                        for item in items:
                            f.write(f"- {item}\n")
                    if not any(report.values()):
                        f.write("\n无任何问题\n")
                    f.write("\n校验完成！\n")
                print(f"校验报告已保存至: {log_file}")
            break
        print("请输入 'y' 或 'n'！")

# 主函数
def main():
    config_content, filename = None, None
    while config_content is None:
        file_path = input("请输入 Clash 配置文件路径（例如 config.ini）：")
        path = Path(file_path)
        if path.is_file():
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    config_content = f.read()
                filename = path.name
                break
            except Exception as e:
                print(f"读取文件失败：{e}")
        else:
            print("文件不存在，请重新输入！")

    while True:
        backup_choice = input("是否备份配置文件？(y/n，默认 n)：").lower() or 'n'
        if backup_choice in ['y', 'n']:
            if backup_choice == 'y':
                backup_path = Path(file_path).with_name(f"{Path(file_path).stem}_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}{Path(file_path).suffix}")
                shutil.copy2(file_path, backup_path)
                print(f"已备份配置文件至: {backup_path}")
            break
        print("请输入 'y' 或 'n'！")

    while True:
        url_choice = input("是否发送网络请求测试 URL 有效性？(y/n，默认 n)：").lower() or 'n'
        if url_choice in ['y', 'n']:
            send_request = (url_choice == 'y')
            break
        print("请输入 'y' 或 'n'！")

    while True:
        latency_choice = input("是否测试 url-test/fallback 的延迟？(y/n，默认 n)：").lower() or 'n'
        if latency_choice in ['y', 'n']:
            test_latency_flag = (latency_choice == 'y')
            break
        print("请输入 'y' 或 'n'！")

    latency_timeout = 5
    if test_latency_flag:
        try:
            timeout = input("请输入延迟测试超时时间（秒，默认 5）：") or '5'
            latency_timeout = float(timeout)
            if latency_timeout <= 0:
                raise ValueError
        except ValueError:
            print("无效输入，使用默认超时时间 5 秒")
            latency_timeout = 5

    report = validate_config(config_content, send_request, test_latency_flag, latency_timeout)
    print_and_log_report(report, filename)

if __name__ == "__main__":
    main()