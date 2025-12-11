#!/usr/bin/env python3
"""
Redfish BMC 发现脚本 - 简化版
只保存发现的IP地址到JSON文件
"""
import subprocess
import argparse
import ipaddress
import requests
import json
import threading
import time
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin
import sys

# 设置日志配置
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# 禁用SSL警告
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class RedfishDiscoverer:
    def __init__(self, threads=50, timeout=5, verify_ssl=False, username='admin', password='0penBmc.'):
        self.threads = threads
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.username = username
        self.password = password
        self.common_ports = [443, 623, 664, 8443, 8888]
        self.redfish_paths = [
            '/redfish/v1/',
            '/redfish/v1',
            '/redfish',
            '/api/redfish/v1/'
        ]
        
        # 结果存储 - 只保存IP地址
        self.discovered_ips = []
        self.valid_credential_ips = []
        self.lock = threading.Lock()
    
    def check_redfish_endpoint(self, base_url):
        """检查单个端点是否支持Redfish"""
        for path in self.redfish_paths:
            try:
                url = urljoin(base_url, path)
                response = requests.get(
                    url,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    allow_redirects=True
                )
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        # 验证是否是Redfish响应
                        if any(key in data for key in ['@odata.context', '@odata.id', 'v1', 'RedfishVersion']):
                            return {
                                'url': url,
                                'data': data
                            }
                    except json.JSONDecodeError:
                        continue
                        
            except (requests.RequestException, ValueError):
                continue
        
        return None
    
    def verify_credentials(self, base_url):
        """验证用户名和密码是否有效"""
        auth_url = urljoin(base_url, '/redfish/v1/Systems')
        
        try:
            response = requests.get(
                auth_url,
                auth=(self.username, self.password),
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=True
            )
            
            return response.status_code == 200
                
        except requests.RequestException:
            return False
    
    def scan_ip(self, ip, ports=None):
        """扫描单个IP地址"""
        if ports is None:
            ports = self.common_ports
        
        for port in ports:
            for protocol in ['https', 'http']:
                base_url = f"{protocol}://{ip}:{port}"
                result = self.check_redfish_endpoint(base_url)
                
                if result:
                    # 验证凭据
                    credentials_valid = self.verify_credentials(base_url)
                    
                    return {
                        'ip': str(ip),
                        'port': port,
                        'protocol': protocol,
                        'credentials_valid': credentials_valid
                    }
        
        return None
    
    def discover_network(self, network_range, ports=None):
        """发现网络范围内的Redfish设备"""
        logging.info(f"开始扫描网络范围: {network_range}")
        logging.info(f"使用端口: {ports or self.common_ports}")
        logging.info(f"验证凭据: {self.username}/{self.password}")
        logging.info("-" * 60)
        
        try:
            network = ipaddress.ip_network(network_range, strict=False)
            total_ips = network.num_addresses
            scanned_count = 0
            
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                # 为每个IP提交扫描任务
                future_to_ip = {
                    executor.submit(self.scan_ip, ip, ports): ip 
                    for ip in network.hosts()
                }
                
                for future in as_completed(future_to_ip):
                    scanned_count += 1
                    ip = future_to_ip[future]
                    
                    try:
                        result = future.result()
                        if result:
                            with self.lock:
                                self.discovered_ips.append(result['ip'])
                                if result['credentials_valid']:
                                    self.valid_credential_ips.append(result['ip'])
                                
                                status = "✅ 有效凭据" if result['credentials_valid'] else "发现"
                                logging.info(f"[{status}] IP: {result['ip']}:{result['port']}")
                    
                    except Exception as e:
                        # 静默处理错误，不打印错误信息
                        pass
                    
                    # 进度显示
                    if scanned_count % 50 == 0:
                        progress = (scanned_count / total_ips) * 100
                        logging.info(f"进度: {scanned_count}/{total_ips} ({progress:.1f}%) - 发现: {len(self.discovered_ips)} IP, 有效凭据: {len(self.valid_credential_ips)} IP")
                        
        except KeyboardInterrupt:
            logging.info("\n用户中断扫描")
        except Exception as e:
            logging.error(f"扫描出错: {e}")
    
    def save_results_and_patch_redfish_targets_configmap(self, only_valid_credentials=True):
        """保存结果到JSON文件 - 按照Prometheus格式保存, 文件名为redfish_targets.json"""
        targets_file = '/tmp/redfish_targets.json'
        
        # 选择要保存的数据（仅IP地址，不包含端口）
        if only_valid_credentials:
            valid_ips = self.valid_credential_ips
        else:
            valid_ips = self.discovered_ips
        
        # 构建Prometheus格式的数据
        prometheus_data = [{
            "targets": valid_ips,  # 仅IP地址，不添加端口号
            "labels": {
                "job": "redfish-remote-targets"
            }
        }]
        
        with open(targets_file, 'w', encoding='utf-8') as f:
            json.dump(prometheus_data, f, indent=2, ensure_ascii=False)
        
        logging.info(f"\n结果已保存到: {targets_file}")
        
        check_cmd = "which kubectl"
        try:
            result = subprocess.run(check_cmd, shell=True, check=True, capture_output=True, text=True)
            logging.info(f"kubectl found at: {result.stdout.strip()}")
        except subprocess.CalledProcessError:
            logging.warning("kubectl not found in PATH")
            return
        
        cmd = f"""kubectl create configmap redfish-targets \
            --from-file=targets.json={targets_file} \
            -n monitoring \
            --dry-run=client \
            -o yaml | kubectl apply -f -"""
            
        try:
            subprocess.run(cmd, shell=True, check=True)
            logging.info("Redfish ConfigMap updated successfully")
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to update Redfish ConfigMap: {e}")
    
    def print_summary(self):
        """打印扫描摘要"""
        logging.info("\n" + "=" * 60)
        logging.info("扫描摘要")
        logging.info("=" * 60)
        logging.info(f"发现的Redfish设备IP数量: {len(self.discovered_ips)}")
        logging.info(f"使用凭据 '{self.username}/{self.password}' 有效的IP数量: {len(self.valid_credential_ips)}")
        
        if self.valid_credential_ips:
            logging.info(f"\n✅ 有效凭据的IP列表:")
            for ip in self.valid_credential_ips:
                logging.info(f"  - {ip}")

def main():
    parser = argparse.ArgumentParser(description='Redfish BMC IP发现工具 - 简化版')
    # parser.add_argument('network', help='要扫描的网络范围 (例如: 192.168.1.0/24)')
    parser.add_argument('networks', nargs='+', help='要扫描的网络范围列表 (例如: 192.168.1.0/24 10.0.0.0/16)')
    parser.add_argument('-p', '--ports', nargs='+', type=int, 
                       help='要扫描的端口列表 (默认: 443 623 664 8443 8888)')
    parser.add_argument('-t', '--threads', type=int, default=100,
                       help='并发线程数 (默认: 100)')
    parser.add_argument('--timeout', type=float, default=5,
                       help='请求超时时间(秒) (默认: 5)')
    parser.add_argument('--verify-ssl', action='store_true',
                       help='验证SSL证书 (默认: 不验证)')
    parser.add_argument('-o', '--output', help='输出结果文件')
    parser.add_argument('--username', default='admin', help='要测试的用户名 (默认: admin)')
    parser.add_argument('--password', default='0penBmc.', help='要测试的密码 (默认: 0penBmc.)')
    parser.add_argument('--only-valid', action='store_true', help='只保存凭据有效的IP')
    parser.add_argument('--quiet', action='store_true', help='安静模式，只输出最终结果')
    parser.add_argument('--interval', type=int, default=20, help='执行间隔（分钟）')
    args = parser.parse_args()
    
    # 如果启用安静模式，调整日志级别
    if args.quiet:
        logging.getLogger().setLevel(logging.WARNING)
    
    while True:
        # 创建发现器实例
        discoverer = RedfishDiscoverer(
            threads=args.threads,
            timeout=args.timeout,
            verify_ssl=args.verify_ssl,
            username=args.username,
            password=args.password
        )
        
        # 开始扫描
        start_time = time.time()
        for network in args.networks:
            discoverer.discover_network(network, args.ports)
        end_time = time.time()
        
        # 输出结果
        discoverer.print_summary()
        logging.info(f"\n扫描耗时: {end_time - start_time:.2f} 秒")
        
        # 保存结果
        if args.output or discoverer.discovered_ips:
            discoverer.save_results_and_patch_redfish_targets_configmap()
        
        if args.interval > 0:
            logging.info(f"\n等待 {args.interval} 分钟后再次执行...")
            time.sleep(args.interval * 60)
        else:
            break  # 如果间隔时间为0，则只执行一次
    
    
if __name__ == "__main__":
    main()