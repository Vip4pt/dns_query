import asyncio
import aiohttp
import dns.asyncresolver
import dns.message
import dns.query
import dns.rdatatype
import ssl
import json
from typing import List, Dict, Optional
import argparse
import sys
from datetime import datetime
from urllib.parse import urlparse
import ipaddress
import time
import threading
from queue import Queue
from colorama import init, Fore, Style

# 初始化colorama
init(autoreset=True)

class RealTimeLogger:
    """实时日志管理器"""
    def __init__(self):
        self.log_queue = Queue()
        self.running = True
        self.log_thread = threading.Thread(target=self._log_worker, daemon=True)
        self.log_thread.start()
        self.total_tasks = 0
        self.completed_tasks = 0
        self.lock = threading.Lock()
    
    def _log_worker(self):
        """日志处理线程"""
        while self.running or not self.log_queue.empty():
            try:
                log_entry = self.log_queue.get(timeout=0.5)
                if log_entry:
                    self._print_log(log_entry)
                    self.log_queue.task_done()
            except:
                continue
    
    def _print_log(self, log_entry):
        """打印日志条目"""
        timestamp, level, message = log_entry
        timestamp_str = timestamp.strftime("%H:%M:%S")
        
        if level == 'INFO':
            print(f"{Fore.CYAN}[{timestamp_str}] {Fore.GREEN}[INFO] {message}")
        elif level == 'WARNING':
            print(f"{Fore.CYAN}[{timestamp_str}] {Fore.YELLOW}[WARNING] {message}")
        elif level == 'ERROR':
            print(f"{Fore.CYAN}[{timestamp_str}] {Fore.RED}[ERROR] {message}")
        elif level == 'SUCCESS':
            print(f"{Fore.CYAN}[{timestamp_str}] {Fore.GREEN}[SUCCESS] {message}")
        elif level == 'PROGRESS':
            progress = self.get_progress()
            print(f"{Fore.CYAN}[{timestamp_str}] {Fore.BLUE}[进度] {message} - {progress}", end='\r')
        else:
            print(f"{Fore.CYAN}[{timestamp_str}] {message}")
    
    def log(self, level, message):
        """添加日志到队列"""
        self.log_queue.put((datetime.now(), level, message))
    
    def set_total_tasks(self, total):
        """设置总任务数"""
        self.total_tasks = total
    
    def task_completed(self):
        """标记任务完成"""
        with self.lock:
            self.completed_tasks += 1
    
    def get_progress(self):
        """获取进度字符串"""
        if self.total_tasks == 0:
            return "0/0 (0%)"
        percentage = (self.completed_tasks / self.total_tasks) * 100
        return f"{self.completed_tasks}/{self.total_tasks} ({percentage:.1f}%)"
    
    def stop(self):
        """停止日志线程"""
        self.running = False
        self.log_thread.join(timeout=1)

class DNSQueryTool:
    def __init__(self, dns_servers_file: str, timeout: int = 5, verbose: bool = True):
        self.timeout = timeout
        self.verbose = verbose
        self.logger = RealTimeLogger() if verbose else None
        self.dns_servers = self.load_dns_servers(dns_servers_file)
        self.results = []
    
    def log(self, level, message):
        """记录日志"""
        if self.verbose and self.logger:
            self.logger.log(level, message)
    
    def detect_protocol(self, address: str) -> str:
        """自动检测DNS服务器的协议类型"""
        address = address.strip().lower()
        
        # DoH (DNS over HTTPS)
        if address.startswith('https://'):
            return 'doh'
        
        # DoT (DNS over TLS)
        if address.startswith('tls://'):
            return 'dot'
        
        # DNS over QUIC (暂时不支持，降级为DoT)
        if address.startswith('quic://'):
            return 'dot'
        
        # 检查是否是IP地址
        try:
            # 移除可能的端口号
            if ':' in address and not address.startswith('['):  # 排除IPv6地址
                ip_part = address.split(':')[0]
                ipaddress.ip_address(ip_part)
            else:
                ipaddress.ip_address(address)
            return 'traditional'  # IP地址，传统DNS
        except ValueError:
            pass
        
        # 默认传统DNS
        return 'traditional'
    
    def parse_dns_address(self, address: str) -> Optional[Dict]:
        """解析DNS地址字符串，返回服务器配置"""
        address = address.strip()
        if not address or address.startswith('#'):
            return None
        
        original_address = address
        
        # 处理常见的格式
        if '://' in address:
            # 有协议前缀
            parsed = urlparse(address)
            protocol = self.detect_protocol(address)
            host = parsed.hostname
            port = parsed.port
            
            if protocol == 'doh':
                # 对于DoH，确保完整的URL
                if not address.endswith('/dns-query'):
                    # 自动添加默认路径
                    address = address.rstrip('/') + '/dns-query'
                return {
                    'address': address,
                    'host': host,
                    'protocol': 'doh',
                    'port': port or 443,
                    'original': original_address
                }
            elif protocol == 'dot':
                return {
                    'address': host,
                    'host': host,
                    'protocol': 'dot',
                    'port': port or 853,
                    'original': original_address
                }
        else:
            # 无协议前缀，传统DNS或IP地址
            if ':' in address:
                parts = address.split(':')
                if len(parts) == 2:  # IPv4:port
                    host, port_str = parts
                    try:
                        port = int(port_str)
                    except ValueError:
                        port = 53
                else:
                    # 可能是IPv6地址
                    if address.startswith('[') and ']' in address:
                        # IPv6地址带端口: [::1]:53
                        host_end = address.find(']')
                        host = address[1:host_end]
                        if ':' in address[host_end:]:
                            port = int(address.split(':')[-1])
                        else:
                            port = 53
                    else:
                        # 纯IPv6地址
                        host = address
                        port = 53
            else:
                host = address
                port = 53
            
            return {
                'address': host,
                'host': host,
                'protocol': 'traditional',
                'port': port,
                'original': original_address
            }
        
        return None
    
    def load_dns_servers(self, file_path: str) -> List[Dict]:
        """加载DNS服务器列表 - 每行一个地址，自动检测协议"""
        servers = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    
                    # 跳过空行和注释
                    if not line or line.startswith('#'):
                        continue
                    
                    # 处理可能的旧格式（逗号分隔）
                    if ',' in line:
                        # 尝试提取第一个部分作为地址
                        parts = line.split(',')
                        address = parts[0].strip()
                        self.log('WARNING', f"第{line_num}行使用旧格式，已自动提取地址部分: {address}")
                    else:
                        address = line
                    
                    # 解析地址
                    server_config = self.parse_dns_address(address)
                    if server_config:
                        servers.append(server_config)
                        self.log('INFO', f"已加载服务器: {server_config['original']} ({server_config['protocol']})")
                    else:
                        self.log('WARNING', f"第{line_num}行无法解析: {line}")
            
            if not servers:
                self.log('ERROR', "未加载到任何有效的DNS服务器")
                sys.exit(1)
            
            self.log('INFO', f"已加载 {len(servers)} 个DNS服务器")
            
            # 按协议统计
            protocols = {}
            for server in servers:
                protocol = server['protocol']
                protocols[protocol] = protocols.get(protocol, 0) + 1
            
            protocol_stats = ", ".join([f"{k}: {v}" for k, v in protocols.items()])
            self.log('INFO', f"协议分布: {protocol_stats}")
            
            return servers
            
        except FileNotFoundError:
            self.log('ERROR', f"文件不存在: {file_path}")
            sys.exit(1)
        except Exception as e:
            self.log('ERROR', f"加载DNS服务器列表时出错: {e}")
            sys.exit(1)
    
    async def query_traditional_dns(self, domain: str, server: Dict, record_type: str = 'A') -> Optional[List[str]]:
        """查询传统DNS (UDP/TCP)"""
        try:
            resolver = dns.asyncresolver.Resolver()
            resolver.nameservers = [server['address']]
            resolver.timeout = self.timeout
            resolver.lifetime = self.timeout
            
            # 尝试UDP
            try:
                if record_type.upper() == 'A':
                    answer = await resolver.resolve(domain, 'A')
                elif record_type.upper() == 'AAAA':
                    answer = await resolver.resolve(domain, 'AAAA')
                else:
                    return None
                
                return [str(r) for r in answer]
            except (dns.exception.Timeout, dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                # UDP失败，尝试TCP
                try:
                    qname = dns.name.from_text(domain)
                    query = dns.message.make_query(qname, dns.rdatatype.from_text(record_type))
                    
                    response = await dns.query.tcp(
                        query,
                        server['address'],
                        timeout=self.timeout,
                        port=server['port']
                    )
                    
                    answers = []
                    for rrset in response.answer:
                        for rr in rrset:
                            answers.append(str(rr))
                    
                    return answers if answers else None
                except Exception:
                    return None
                    
        except Exception as e:
            self.log('ERROR', f"传统DNS查询失败: {domain}@{server['original']} - {str(e)}")
            return None
    
    async def query_dot(self, domain: str, server: Dict, record_type: str = 'A') -> Optional[List[str]]:
        """查询DNS over TLS"""
        try:
            # 创建TLS上下文
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            
            # 创建DNS查询消息
            qname = dns.name.from_text(domain)
            query = dns.message.make_query(qname, dns.rdatatype.from_text(record_type))
            
            # 发送DoT查询
            response = await dns.query.tls(
                query,
                server['address'],
                port=server['port'],
                timeout=self.timeout,
                ssl_context=ssl_context
            )
            
            # 解析响应
            answers = []
            for rrset in response.answer:
                for rr in rrset:
                    answers.append(str(rr))
            
            return answers if answers else None
            
        except Exception as e:
            self.log('ERROR', f"DoT查询失败: {domain}@{server['original']} - {str(e)}")
            return None
    
    async def query_doh(self, domain: str, server: Dict, record_type: str = 'A') -> Optional[List[str]]:
        """查询DNS over HTTPS"""
        try:
            doh_url = server['address']
            
            # 准备查询参数
            params = {
                'name': domain,
                'type': record_type
            }
            headers = {
                'Accept': 'application/dns-json'
            }
            
            # 发送DoH查询
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            connector = aiohttp.TCPConnector(ssl=False)
            async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
                async with session.get(doh_url, params=params, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        # 解析响应
                        answers = []
                        if 'Answer' in data:
                            for answer in data['Answer']:
                                if answer['type'] == 1:  # A记录
                                    answers.append(answer['data'])
                                elif answer['type'] == 28:  # AAAA记录
                                    answers.append(answer['data'])
                        
                        return answers if answers else None
                    else:
                        self.log('WARNING', f"DoH查询返回非200状态码: {domain}@{server['original']} - {response.status}")
                        return None
                        
        except Exception as e:
            self.log('ERROR', f"DoH查询失败: {domain}@{server['original']} - {str(e)}")
            return None
    
    async def query_domain(self, domain: str, server: Dict, task_id: int) -> Dict:
        """查询单个域名的A和AAAA记录"""
        result = {
            'server': server['original'],
            'protocol': server['protocol'],
            'domain': domain,
            'a_records': [],
            'aaaa_records': [],
            'status': 'success',
            'response_time': None
        }
        
        start_time = time.time()
        
        try:
            # 开始查询
            self.log('INFO', f"[任务{task_id}] 开始查询: {domain} @ {server['original']}")
            
            # 根据协议选择查询方法
            if server['protocol'] == 'traditional':
                a_result = await self.query_traditional_dns(domain, server, 'A')
                aaaa_result = await self.query_traditional_dns(domain, server, 'AAAA')
            elif server['protocol'] == 'dot':
                a_result = await self.query_dot(domain, server, 'A')
                aaaa_result = await self.query_dot(domain, server, 'AAAA')
            elif server['protocol'] == 'doh':
                a_result = await self.query_doh(domain, server, 'A')
                aaaa_result = await self.query_doh(domain, server, 'AAAA')
            else:
                result['status'] = 'error'
                result['error'] = f"不支持的协议: {server['protocol']}"
                self.log('ERROR', f"[任务{task_id}] 不支持的协议: {server['protocol']}")
                return result
            
            result['a_records'] = a_result or []
            result['aaaa_records'] = aaaa_result or []
            
            if not result['a_records'] and not result['aaaa_records']:
                result['status'] = 'no_records'
                self.log('WARNING', f"[任务{task_id}] 无记录: {domain} @ {server['original']}")
            else:
                # 显示查询结果
                record_info = []
                if result['a_records']:
                    record_info.append(f"A:{len(result['a_records'])}")
                if result['aaaa_records']:
                    record_info.append(f"AAAA:{len(result['aaaa_records'])}")
                
                if record_info:
                    response_time = round((time.time() - start_time) * 1000, 2)
                    self.log('SUCCESS', f"[任务{task_id}] 查询成功: {domain} @ {server['original']} ({' '.join(record_info)}, {response_time}ms)")
                
        except Exception as e:
            result['status'] = 'error'
            result['error'] = str(e)
            self.log('ERROR', f"[任务{task_id}] 查询异常: {domain} @ {server['original']} - {str(e)}")
        
        result['response_time'] = round((time.time() - start_time) * 1000, 2)  # 毫秒
        
        return result
    
    async def batch_query(self, domains: List[str], max_concurrent: int = 20) -> List[Dict]:
        """批量查询多个域名"""
        all_results = []
        
        # 创建任务列表
        tasks = []
        task_counter = 0
        
        for domain in domains:
            for server in self.dns_servers:
                task_counter += 1
                tasks.append((task_counter, domain, server))
        
        total_tasks = len(tasks)
        self.logger.set_total_tasks(total_tasks)
        
        # 显示查询摘要
        self.log('INFO', f"准备查询 {len(domains)} 个域名 × {len(self.dns_servers)} 个DNS服务器 = {total_tasks} 个查询任务")
        self.log('INFO', f"最大并发数: {max_concurrent}, 超时时间: {self.timeout}秒")
        
        # 限制并发数
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def query_with_semaphore(task_id, domain, server):
            async with semaphore:
                result = await self.query_domain(domain, server, task_id)
                # 更新进度
                self.logger.task_completed()
                self.log('PROGRESS', f"查询进度")
                return result
        
        # 执行所有查询
        if tasks:
            try:
                # 创建所有异步任务
                async_tasks = []
                for task_id, domain, server in tasks:
                    async_tasks.append(query_with_semaphore(task_id, domain, server))
                
                # 等待所有任务完成
                self.log('INFO', "开始执行查询任务...")
                results = await asyncio.gather(*async_tasks, return_exceptions=True)
                
                # 处理结果
                for i, r in enumerate(results):
                    if not isinstance(r, Exception):
                        all_results.append(r)
                    else:
                        self.log('ERROR', f"任务异常: {str(r)}")
                        
                # 显示最终进度
                self.log('SUCCESS', f"查询完成! 成功: {len(all_results)}/{total_tasks} 个查询")
                
            except Exception as e:
                self.log('ERROR', f"批量查询时出错: {e}")
                import traceback
                traceback.print_exc()
        
        self.results = all_results
        return all_results
    
    def print_summary(self):
        """打印统计摘要"""
        if not self.results:
            print(f"{Fore.YELLOW}没有查询结果")
            return
        
        total_queries = len(self.results)
        successful = sum(1 for r in self.results if r['status'] == 'success')
        errors = sum(1 for r in self.results if r['status'] == 'error')
        no_records = sum(1 for r in self.results if r['status'] == 'no_records')
        
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}查询统计摘要")
        print(f"{Fore.CYAN}{'='*60}")
        print(f"{Fore.WHITE}总查询次数: {total_queries}")
        if total_queries > 0:
            success_rate = successful/total_queries*100
            no_record_rate = no_records/total_queries*100
            error_rate = errors/total_queries*100
            
            print(f"{Fore.GREEN}成功: {successful} ({success_rate:.1f}%)")
            print(f"{Fore.YELLOW}无记录: {no_records} ({no_record_rate:.1f}%)")
            print(f"{Fore.RED}错误: {errors} ({error_rate:.1f}%)")
        
        # 计算平均响应时间
        response_times = [r['response_time'] for r in self.results if r['response_time']]
        if response_times:
            avg_time = sum(response_times) / len(response_times)
            print(f"{Fore.WHITE}平均响应时间: {avg_time:.2f}ms")
        
        # 显示最快的服务器
        if self.results:
            successful_results = [r for r in self.results if r['status'] == 'success' and r['response_time']]
            if successful_results:
                fastest = min(successful_results, key=lambda x: x['response_time'])
                print(f"{Fore.GREEN}最快响应: {fastest['server']} - {fastest['response_time']}ms")
    
    def print_results(self, output_format: str = 'table', show_details: bool = False):
        """打印查询结果"""
        if output_format == 'json':
            print(json.dumps(self.results, indent=2, ensure_ascii=False))
            return
        
        if output_format == 'csv':
            # CSV格式输出
            print("服务器,协议,域名,状态,A记录,AAAA记录,响应时间(ms)")
            for result in self.results:
                a_records = ';'.join(result['a_records']) if result['a_records'] else ''
                aaaa_records = ';'.join(result['aaaa_records']) if result['aaaa_records'] else ''
                response_time = result['response_time'] or 0
                print(f"{result['server']},{result['protocol']},{result['domain']},{result['status']},{a_records},{aaaa_records},{response_time}")
            return
        
        # 表格格式输出
        print(f"\n{Fore.CYAN}{'='*80}")
        print(f"{Fore.CYAN}DNS查询结果 - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{Fore.CYAN}{'='*80}")
        
        # 按域名分组显示结果
        domain_groups = {}
        for result in self.results:
            domain = result['domain']
            if domain not in domain_groups:
                domain_groups[domain] = []
            domain_groups[domain].append(result)
        
        for domain, results in domain_groups.items():
            print(f"\n{Fore.YELLOW}[域名] {domain}")
            print(f"{Fore.WHITE}{'-'*40}")
            
            # 收集所有不同的A和AAAA记录
            all_a_records = set()
            all_aaaa_records = set()
            
            for result in results:
                all_a_records.update(result['a_records'])
                all_aaaa_records.update(result['aaaa_records'])
                
                if show_details:
                    if result['status'] == 'success':
                        status_color = Fore.GREEN
                        status_symbol = '✓'
                    elif result['status'] == 'no_records':
                        status_color = Fore.YELLOW
                        status_symbol = '○'
                    else:
                        status_color = Fore.RED
                        status_symbol = '✗'
                    
                    record_count = 0
                    if result['a_records']:
                        record_count += len(result['a_records'])
                    if result['aaaa_records']:
                        record_count += len(result['aaaa_records'])
                    
                    print(f"  {status_color}{status_symbol} {result['server']} ({result['protocol']}) - {record_count}记录 - {result['response_time']}ms")
            
            # 显示记录汇总
            if all_a_records:
                print(f"{Fore.GREEN}  A记录: {', '.join(sorted(all_a_records))}")
            else:
                print(f"{Fore.YELLOW}  A记录: 无")
            
            if all_aaaa_records:
                print(f"{Fore.CYAN}  AAAA记录: {', '.join(sorted(all_aaaa_records))}")
            else:
                print(f"{Fore.YELLOW}  AAAA记录: 无")
        
        self.print_summary()
    
    def save_results(self, output_file: str):
        """保存结果到文件"""
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=2, ensure_ascii=False)
            print(f"\n{Fore.GREEN}详细结果已保存到: {output_file}")
        except Exception as e:
            print(f"{Fore.RED}保存结果时出错: {e}")
    
    def cleanup(self):
        """清理资源"""
        if self.logger:
            self.logger.stop()

def create_example_config(file_path: str = "dns_servers.txt"):
    """创建示例DNS服务器配置文件"""
    example_content = """# DNS服务器列表 - 每行一个地址，自动检测协议

# 公共DNS服务器 (传统DNS)
8.8.8.8
8.8.4.4
1.1.1.1
1.0.0.1
9.9.9.9
149.112.112.112
208.67.222.222
208.67.220.220
114.114.114.114
114.114.115.115
223.5.5.5
223.6.6.6
119.29.29.29
180.76.76.76

# DNS over HTTPS (DoH)
https://cloudflare-dns.com/dns-query
https://dns.google/dns-query
https://dns.quad9.net/dns-query
https://doh.opendns.com/dns-query

# DNS over TLS (DoT)
tls://1.1.1.1
tls://8.8.8.8
tls://9.9.9.9

# 也可以指定端口
8.8.8.8:53
1.1.1.1:853  # 这将作为传统DNS查询，端口853
"""
    
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(example_content)
    print(f"{Fore.GREEN}已创建示例配置文件: {file_path}")

def main():
    parser = argparse.ArgumentParser(
        description='批量DNS查询工具 - 支持传统DNS/DoT/DoH，实时日志输出',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  python dns_query.py -c dns_servers.txt -d example.com
  python dns_query.py -c dns_servers.txt -d "google.com baidu.com"
  python dns_query.py -c dns_servers.txt -f domains.txt
  python dns_query.py --create-example  # 创建示例配置文件
        """
    )
    
    parser.add_argument('-c', '--config', required=True, help='DNS服务器列表文件')
    parser.add_argument('-d', '--domains', nargs='+', help='要查询的域名列表')
    parser.add_argument('-f', '--file', help='包含域名的文件(每行一个)')
    parser.add_argument('-o', '--output', help='输出结果文件')
    parser.add_argument('--format', choices=['table', 'json', 'csv'], default='table', help='输出格式')
    parser.add_argument('--details', action='store_true', help='显示详细结果')
    parser.add_argument('--timeout', type=int, default=5, help='查询超时时间(秒)')
    parser.add_argument('--concurrent', type=int, default=10, help='并发查询数')
    parser.add_argument('--quiet', action='store_true', help='安静模式，不显示实时日志')
    parser.add_argument('--create-example', action='store_true', help='创建示例配置文件')
    
    args = parser.parse_args()
    
    if args.create_example:
        create_example_config()
        return
    
    # 获取域名列表
    domains = []
    if args.domains:
        domains.extend(args.domains)
    if args.file:
        try:
            with open(args.file, 'r', encoding='utf-8') as f:
                domains.extend([line.strip() for line in f if line.strip()])
        except Exception as e:
            print(f"{Fore.RED}读取域名文件时出错: {e}")
            sys.exit(1)
    
    if not domains:
        # 如果命令行没有提供域名，从标准输入读取
        print(f"{Fore.YELLOW}请输入要查询的域名（每行一个，空行结束）:")
        try:
            while True:
                line = input().strip()
                if not line:
                    break
                domains.append(line)
        except EOFError:
            pass
    
    if not domains:
        print(f"{Fore.RED}错误: 没有指定要查询的域名")
        parser.print_help()
        sys.exit(1)
    
    # 创建并运行查询工具
    tool = None
    try:
        verbose = not args.quiet
        print(f"{Fore.CYAN}初始化DNS查询工具...{'（安静模式）' if not verbose else ''}")
        tool = DNSQueryTool(args.config, args.timeout, verbose)
        
        # 运行异步查询
        if verbose:
            print(f"{Fore.CYAN}开始查询 {len(domains)} 个域名...")
        else:
            print(f"{Fore.CYAN}开始查询 {len(domains)} 个域名 × {len(tool.dns_servers)} 个DNS服务器...")
        
        results = asyncio.run(tool.batch_query(domains, args.concurrent))
        
        # 打印结果（清除进度行）
        print()  # 空行
        tool.print_results(args.format, args.details)
        
        # 保存结果
        if args.output:
            tool.save_results(args.output)
            
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}查询被用户中断")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}运行时出错: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        if tool:
            tool.cleanup()

if __name__ == "__main__":
    main()
