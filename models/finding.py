from typing import Any
from pydantic import BaseModel
from datetime import datetime
from models.event import Event


class Finding(BaseModel):

    # Finding 唯一 ID
    finding_id: str = "unknown"

    # 检测类型，例如 ssh_bruteforce
    finding_type: str = "unknown"

    # 人类可读标题
    title: str = "unknown"

    # 检测结果描述
    description: str = "unknown"

    # low / medium / high / critical
    severity: str = "unknown"

    # linux / windows / web
    source: str = "unknown"

    # 涉及的主机
    host: str = "unknown"

    # 涉及的用户
    user: str = "unknown"

    # 攻击源 IP
    src_ip: str = "unknown"

    # 目标 IP
    dst_ip: str = "unknown"

    # Finding 开始时间
    start_time: datetime | None = None

    # Finding 结束时间
    end_time: datetime | None = None

    # 相关事件数量
    event_count: int = 0

    # 支撑 Finding 的原始 Event
    events: list[Event] = []

    # Detector 特有数据
    attributes: dict[str, Any] = {}

    # 标签
    tags: list[str] = []

    # Schema version
    schema_version: str = "1.0"