import requests
import json
import logging
from typing import Dict, List, Optional, Any
from urllib.parse import urljoin, urlparse
import urllib3
import requests
import json
import logging
from typing import Dict, List, Optional, Any
from urllib.parse import urljoin, urlparse
import urllib3
import ipaddress
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import subprocess
# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class RedfishClient:
    """Redfish API 客户端"""

    def __init__(self, host: str, username: str, password: str,
                 verify_ssl: bool = False, timeout: int = 10):
        """
        初始化Redfish客户端

        Args:
            host: BMC IP地址或主机名
            username: 用户名
            password: 密码
            verify_ssl: 是否验证SSL证书
            timeout: 请求超时时间
        """
        self.host = host
        self.base_url = f"https://{host}"
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.session = None
        self.token = None
        self.root_data = None

        # 配置日志
        self.logger = logging.getLogger(__name__)

    def connect(self) -> bool:
        """
        连接到Redfish服务（不验证凭据）

        Returns:
            bool: 连接是否成功
        """
        try:
            # 获取根目录验证连接
            response = requests.get(
                f"{self.base_url}/redfish/v1",
                verify=self.verify_ssl,
                timeout=self.timeout
            )

            if response.status_code == 200:
                self.root_data = response.json()
                self.logger.info(f"成功连接到 {self.host}")
                self.logger.debug(f"Redfish版本: {self.root_data.get('RedfishVersion', 'N/A')}")
                return True
            else:
                self.logger.error(f"连接失败: HTTP {response.status_code}")
                return False

        except requests.exceptions.RequestException as e:
            self.logger.error(f"连接错误: {e}")
            return False
    def create_session(self) -> bool:
        """
        创建会话获取token

        Returns:
            bool: 会话创建是否成功
        """
        try:
            session_url = f"{self.base_url}/redfish/v1/SessionService/Sessions"
            headers = {
                'Content-Type': 'application/json'
            }
            payload = {
                'UserName': self.username,
                'Password': self.password
            }

            response = requests.post(
                session_url,
                json=payload,
                headers=headers,
                verify=self.verify_ssl,
                timeout=self.timeout
            )

            if response.status_code == 201:
                self.token = response.headers.get('X-Auth-Token')
                self.session_id = response.headers.get('Location')
                self.logger.info("会话创建成功")
                return True
            else:
                self.logger.error(f"会话创建失败: HTTP {response.status_code}")
                return False

        except requests.exceptions.RequestException as e:
            self.logger.error(f"会话创建错误: {e}")
            return False

    def _request(self, method: str, endpoint: str, **kwargs) -> Optional[Dict]:
        """
        发送HTTP请求

        Args:
            method: HTTP方法 (GET, POST, PATCH, DELETE)
            endpoint: API端点

        Returns:
            Optional[Dict]: 响应数据或None
        """
        url = urljoin(self.base_url, endpoint)

        # 设置默认头
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }

        # 添加认证token（如果存在）
        if self.token:
            headers['X-Auth-Token'] = self.token
            auth = None
        else:
            auth = (self.username, self.password)

        try:
            response = requests.request(
                method=method,
                url=url,
                auth=auth,
                headers={**headers, **kwargs.get('headers', {})},
                json=kwargs.get('json'),
                data=kwargs.get('data'),
                params=kwargs.get('params'),
                verify=self.verify_ssl,
                timeout=self.timeout
            )

            # 记录请求详情
            self.logger.debug(f"{method} {endpoint} - HTTP {response.status_code}")

            if response.status_code == 401 and self.token:
                # Token可能过期，尝试重新登录
                self.logger.warning("Token可能过期，尝试重新登录")
                if self.create_session():
                    # 使用新token重试
                    headers['X-Auth-Token'] = self.token
                    response = requests.request(
                        method=method,
                        url=url,
                        headers=headers,
                        json=kwargs.get('json'),
                        verify=self.verify_ssl,
                        timeout=self.timeout
                    )

            # 处理响应
            if response.status_code in [200, 201, 202, 204]:
                if response.content:
                    try:
                        return response.json()
                    except json.JSONDecodeError:
                        return {'raw': response.text}
                return {}
            else:
                self.logger.error(f"请求失败 {method} {endpoint}: HTTP {response.status_code}")
                self.logger.debug(f"响应: {response.text[:500]}")
                return None

        except requests.exceptions.RequestException as e:
            self.logger.error(f"请求异常 {method} {endpoint}: {e}")
            return None

    def get(self, endpoint: str) -> Optional[Dict]:
        """GET请求"""
        return self._request('GET', endpoint)

    def post(self, endpoint: str, data: Dict) -> Optional[Dict]:
        """POST请求"""
        return self._request('POST', endpoint, json=data)

    def patch(self, endpoint: str, data: Dict) -> Optional[Dict]:
        """PATCH请求"""
        return self._request('PATCH', endpoint, json=data)

    def delete(self, endpoint: str) -> Optional[Dict]:
        """DELETE请求"""
        return self._request('DELETE', endpoint)

    def close(self):
        """关闭会话"""
        if hasattr(self, 'session_id') and self.session_id:
            try:
                self.delete(self.session_id)
                self.logger.info("会话已关闭")
            except:
                pass
        self.token = None

    def validate_credentials(self) -> bool:
        """
        验证用户名和密码是否正确
        
        Returns:
            bool: 凭据是否有效
        """
        return self.create_session()

def main():
    """网络扫描并验证密码，只记录有效的IP地址"""
    import sys
    import time as time_module  # 避免与已导入的time冲突

    # 配置日志
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

    # 扫描配置
    max_workers = 50  # 最大并发线程数
    scan_interval = 20 * 60  # 20分钟间隔（秒）

    while True:  # 无限循环
        # 从Secret获取用户名和密码
        credentials = get_credentials_from_secret()
        if credentials:
            username, password = credentials
        else:
            print("无法从Secret获取凭据，使用默认凭据")
            username = "admin"
            password = "0penBmc."
        # 从ConfigMap获取要扫描的网段列表
        networks = get_networks_from_configmap()
        if not networks:
            print("无法获取网段列表，使用默认网段")
            networks = ["192.168.11.0/24"]  # 默认网段
        
        print("=== 开始扫描Redfish设备 ===")
        
        # 存储发现的有效设备IP
        valid_ips = []
        
        # 扫描每个网段
        for network in networks:
            print(f"\n正在扫描网段: {network}")
            
            try:
                # 创建IP网络对象
                net = ipaddress.ip_network(network, strict=False)
                hosts = [str(ip) for ip in net.hosts()]
                print(f"网段 {network} 包含 {len(hosts)} 个主机")
                
            except ValueError as e:
                print(f"无效的网络地址: {network}")
                continue

            # 使用线程池并发扫描
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                # 提交所有扫描任务
                future_to_host = {
                    executor.submit(scan_host, host, username, password): host
                    for host in hosts
                }

                # 收集扫描结果
                for future in as_completed(future_to_host):
                    host = future_to_host[future]
                    try:
                        result = future.result()
                        if result:
                            valid_ips.append(result)
                            print(f"  发现有效设备: {result}")
                    except Exception as e:
                        pass  # 忽略单个主机的扫描错误

        print(f"\n=== 扫描完成 ===")
        print(f"总共发现 {len(valid_ips)} 个有效Redfish设备")
        
        # 显示所有有效IP
        for ip in valid_ips:
            print(f"  - {ip}")
            
        save_results_and_patch_redfish_targets_configmap(valid_ips)
        
        print(f"\n等待 {scan_interval} 秒 ({scan_interval//60} 分钟) 后进行下次扫描...")
        time_module.sleep(scan_interval)  # 等待20分钟

def get_networks_from_configmap():
    """
    从Kubernetes ConfigMap中获取要扫描的网段列表
    
    Returns:
        list: 网段列表
    """
    import tempfile
    import os
    
    # 检查kubectl是否存在
    check_cmd = "which kubectl"
    try:
        result = subprocess.run(check_cmd, shell=True, check=True, capture_output=True, text=True)
        logging.info(f"kubectl found at: {result.stdout.strip()}")
    except subprocess.CalledProcessError:
        logging.warning("kubectl not found in PATH")
        return None
    
    # 创建临时文件存储ConfigMap数据
    with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as temp_file:
        temp_filename = temp_file.name
    
    try:
        # 从ConfigMap获取数据
        cmd = f"kubectl get configmap redfish-scanned-networks -n monitoring -o jsonpath='{{.data.networks\\.json}}' > {temp_filename}"
        subprocess.run(cmd, shell=True, check=True)
        
        # 读取并解析JSON数据
        with open(temp_filename, 'r') as f:
            content = f.read().strip()
            if content:
                import json
                data = json.loads(content)
                return data.get("networks", [])
            else:
                return None
    except subprocess.CalledProcessError as e:
        logging.error(f"无法从ConfigMap获取网段列表: {e}")
        return None
    except json.JSONDecodeError as e:
        logging.error(f"无法解析ConfigMap中的JSON数据: {e}")
        return None
    finally:
        # 清理临时文件
        if os.path.exists(temp_filename):
            os.unlink(temp_filename)
    
    return None
    
def save_results_and_patch_redfish_targets_configmap(valid_ips):
        """保存结果到JSON文件 - 按照Prometheus格式保存, 文件名为redfish_targets.json"""
        targets_file = '/tmp/redfish_targets.json'
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

def get_credentials_from_secret():
    """
    从Kubernetes Secret中获取Redfish BMC凭据
    
    Returns:
        tuple: (username, password) 或 None（如果获取失败）
    """
    import base64
    
    # 检查kubectl是否存在
    check_cmd = "which kubectl"
    try:
        result = subprocess.run(check_cmd, shell=True, check=True, capture_output=True, text=True)
        logging.info(f"kubectl found at: {result.stdout.strip()}")
    except subprocess.CalledProcessError:
        logging.warning("kubectl not found in PATH")
        return None
    
    try:
        # 获取用户名
        username_cmd = "kubectl get secret redfish-bmc-credentials -n monitoring -o jsonpath='{.data.username}'"
        username_result = subprocess.run(username_cmd, shell=True, check=True, capture_output=True, text=True)
        encoded_username = username_result.stdout.strip()
        
        # 获取密码
        password_cmd = "kubectl get secret redfish-bmc-credentials -n monitoring -o jsonpath='{.data.password}'"
        password_result = subprocess.run(password_cmd, shell=True, check=True, capture_output=True, text=True)
        encoded_password = password_result.stdout.strip()
        
        # 解码base64编码的凭据
        username = base64.b64decode(encoded_username).decode('utf-8')
        password = base64.b64decode(encoded_password).decode('utf-8')
        
        return (username, password)
    except subprocess.CalledProcessError as e:
        logging.error(f"无法从Secret获取凭据: {e}")
        return None
    except Exception as e:
        logging.error(f"解码凭据时出错: {e}")
        return None

def scan_host(host: str, username: str, password: str) -> Optional[str]:
    """
    扫描单个主机并验证凭据
    
    Args:
        host: 主机IP地址
        username: 用户名
        password: 密码
        
    Returns:
        Optional[str]: 主机IP地址，如果无效则返回None
    """
    try:
        # 创建客户端实例
        client = RedfishClient(
            host=host,
            username=username,
            password=password
        )
        
        # 检查是否支持Redfish
        if client.connect():
            # 验证凭据是否正确
            if client.validate_credentials():
                # 只返回IP地址
                return host
    except Exception as e:
        pass  # 忽略单个主机的错误
    
    return None
if __name__ == "__main__":
    main()
