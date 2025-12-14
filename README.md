# DNS 查询工具功能说明

---

## 1. 依赖说明与安装

### 1.1 第三方依赖

```bash
pip install colorama dnspython aiohttp
```

### 1.2 依赖库说明

下表列出了本工具使用到的主要 Python 标准库与第三方库，并说明其用途：

| 库名                | 类型             | 作用说明                                 |
| ----------------- | -------------- | ------------------------------------ |
| asyncio           | 标准库            | 提供异步事件循环，用于高并发 DNS 查询调度              |
| aiohttp           | 第三方            | 异步 HTTP 客户端，用于 DoH（DNS over HTTPS）请求 |
| dns.asyncresolver | 第三方（dnspython） | 异步 DNS 解析器，支持高并发传统 DNS 查询            |
| dns.message       | 第三方（dnspython） | 构造与解析 DNS 协议消息                       |
| dns.query         | 第三方（dnspython） | 低层 DNS 查询实现（UDP/TCP）                 |
| dns.rdatatype     | 第三方（dnspython） | DNS 记录类型枚举（A / AAAA / MX 等）          |
| ssl               | 标准库            | TLS/SSL 支持，用于安全的 HTTPS 查询            |
| json              | 标准库            | 查询结果的序列化与 JSON 格式输出                  |
| argparse          | 标准库            | 命令行参数解析                              |
| sys               | 标准库            | 系统级参数与退出控制                           |
| datetime          | 标准库            | 时间戳生成与格式化输出                          |
| urllib.parse      | 标准库            | URL 解析（用于 DoH 服务器地址处理）               |
| ipaddress         | 标准库            | IP 地址合法性校验（IPv4 / IPv6）              |
| time              | 标准库            | 响应时间统计与延迟计算                          |
| threading         | 标准库            | 线程池与并发控制（非异步场景补充）                    |
| queue.Queue       | 标准库            | 线程安全的任务与结果队列                         |
| colorama          | 第三方            | 跨平台终端彩色日志输出                          |

### 1.3 依赖设计说明

* **优先使用标准库**，减少外部依赖数量，提升部署与兼容性
* **异步 + 线程混合模型**：

  * asyncio / aiohttp / dns.asyncresolver 负责高并发 I/O
  * threading + Queue 用于兼容阻塞式 DNS 查询与结果汇总
* **dnspython** 作为核心 DNS 协议实现，保证解析准确性与灵活性
* **colorama** 为唯一必需的显示增强依赖，不影响核心功能

> 除 `colorama` 与 `dnspython` / `aiohttp` 外，其余均为 Python 标准库，无需额外安装。

````

---

## 2. 主要改进

### 2.1 实时日志输出

- 显示**每个查询任务**的开始与结束状态
- 使用**彩色输出**，便于区分不同类型的日志信息
- 提供**进度条**，实时展示查询执行进度

### 2.2 日志级别定义

| 日志级别 | 含义说明 | 显示颜色 |
|---------|----------|----------|
| INFO | 常规运行信息 | 绿色 |
| SUCCESS | 查询成功 | 绿色 |
| WARNING | 警告信息 | 黄色 |
| ERROR | 错误信息 | 红色 |
| PROGRESS | 进度提示 | 蓝色 |

### 2.3 任务编号

- 每个 DNS 查询都会分配一个**唯一任务编号**
- 便于在并发执行时进行日志追踪与问题定位

### 2.4 进度显示

- 实时显示：
  - 已完成任务数 / 总任务数
  - 完成百分比（%）

### 2.5 安静模式（Quiet Mode）

- 通过 `--quiet` 参数关闭实时日志输出
- 适合脚本调用或仅关心最终结果的场景

---

## 3. 使用示例

### 3.1 默认模式（开启实时日志）

```bash
python dns_query.py -c dns_servers.txt -d google.com
````

### 3.2 安静模式（关闭实时日志）

```bash
python dns_query.py -c dns_servers.txt -d google.com --quiet
```

### 3.3 查询多个域名

```bash
python dns_query.py -c dns_servers.txt -d google.com baidu.com github.com
```

### 3.4 从文件读取域名列表

```bash
python dns_query.py -c dns_servers.txt -f domains.txt
```

### 3.5 显示详细结果

```bash
python dns_query.py -c dns_servers.txt -d google.com --details
```

### 3.6 输出 JSON 格式结果

```bash
python dns_query.py -c dns_servers.txt -d google.com --format json
```

### 3.7 保存查询结果到文件

```bash
python dns_query.py -c dns_servers.txt -d google.com -o results.json
```

---

## 4. 实时日志示例输出

```text
[14:30:25] [INFO] 初始化DNS查询工具...
[14:30:25] [INFO] 已加载服务器: 8.8.8.8 (traditional)
[14:30:25] [INFO] 已加载服务器: 1.1.1.1 (traditional)
[14:30:25] [INFO] 已加载 2 个DNS服务器
[14:30:25] [INFO] 协议分布: traditional: 2
[14:30:25] [INFO] 准备查询 1 个域名 × 2 个DNS服务器 = 2 个查询任务
[14:30:25] [INFO] 最大并发数: 10, 超时时间: 5秒
[14:30:25] [INFO] 开始执行查询任务...
[14:30:25] [INFO] [任务1] 开始查询: google.com @ 8.8.8.8
[14:30:25] [INFO] [任务2] 开始查询: google.com @ 1.1.1.1
[14:30:25] [进度] 查询进度 - 0/2 (0%)

[14:30:25] [SUCCESS] [任务1] 查询成功: google.com @ 8.8.8.8 (A:1, 45.67ms)
[14:30:25] [进度] 查询进度 - 1/2 (50%)

[14:30:25] [SUCCESS] [任务2] 查询成功: google.com @ 1.1.1.1 (A:1 AAAA:1, 52.12ms)
[14:30:25] [进度] 查询进度 - 2/2 (100%)

[14:30:25] [SUCCESS] 查询完成! 成功: 2/2 个查询
```

---

## 5. 查询结果示例

```text
==========================================
DNS查询结果 - 2023-12-14 14:30:25
==========================================

[域名] google.com
----------------------------------------
  ✓ 8.8.8.8 (traditional) - 1记录 - 45.67ms
  ✓ 1.1.1.1 (traditional) - 2记录 - 52.12ms

  A记录:
    - 142.250.185.78

  AAAA记录:
    - 2404:6800:4005:800::200e
```

---

## 6. 查询统计摘要

```text
==========================================
查询统计摘要
==========================================
总查询次数: 2
成功: 2 (100.0%)
无记录: 0 (0.0%)
错误: 0 (0.0%)
平均响应时间: 48.90ms
最快响应: 8.8.8.8 - 45.67ms
```

---

## 7. 配置文件示例

### 7.1 创建示例配置文件

```bash
python dns_query.py --create-example
```

> 该命令将自动生成 `dns_servers.txt`，其中包含多种类型的 DNS 服务器配置示例。

---

## 8. 新功能亮点总结

* 彩色日志输出，提升可读性
* 实时进度展示，直观掌握执行状态
* 完整的任务生命周期日志（开始 / 成功 / 失败）
* 详细的错误原因报告，便于排障
* 任务编号机制，支持高并发场景下的精准追踪
* 线程与资源的安全回收，提升稳定性

---

> 该工具适用于 DNS 性能测试、解析一致性验证、多服务器对比等专业场景。
