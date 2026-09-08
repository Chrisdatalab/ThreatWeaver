from pydantic import BaseModel
from typing import Any

#BaseModel做数据验证
class Event(BaseModel):
    # 事件唯一 ID / Unique event ID
    event_id: str = "unknown"

    # 事件发生时间 / Event timestamp
    timestamp: str = "unknown"

    # 日志来源：linux / windows / web
    # Log source: linux / windows / web
    source: str = "unknown"

    # 标准化事件类型 / Normalized event type
    event_type: str = "unknown"

    # 主机名 / Hostname
    host: str = "unknown"

    # 用户名 / Username
    user: str = "unknown"

    # 进程名 / Process name
    process: str = "unknown"

    # 进程 ID / Process ID
    pid: int | None = None

    # 源 IP 地址 / Source IP address
    src_ip: str = "unknown"

    # 源端口 / Source port
    src_port: int | None = None

    # 目标 IP 地址 / Destination IP address
    dst_ip: str = "unknown"

    # 目标端口 / Destination port
    dst_port: int | None = None

    # 执行动作 / Action performed
    action: str = "unknown"

    # 执行结果：success / failure / unknown
    # Action outcome: success / failure / unknown
    outcome: str = "unknown"

    # 标准化后的事件信息 / Normalized event message
    message: str = "unknown"

    # 原始日志内容 / Raw log entry
    raw: str

    # 日志特有的扩展字段 / Source-specific extra attributes
    attributes: dict[str, Any] = {}

    # 事件标签 / Event tags
    tags: list[str] = []

    # 原始日志文件 / Source log file
    source_file: str = "unknown"

    # 原始日志所在行号 / Original log line number
    line_number: int | None = None

    # Event 数据结构版本 / Event schema version
    schema_version: str = "1.0"