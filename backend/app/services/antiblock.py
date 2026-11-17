"""反爬对抗业务规则：状态流转、字段校验与筛选口径都收在这里。"""
from __future__ import annotations

from typing import Any

from app.services.risk import parse_threshold, risk_service
from app.store import store

MODULE = "antiblock"
LIST_FIELDS = ["策略编号", "策略名称", "触发条件", "延迟范围", "UA伪装", "Referer生成", "Cookie策略", "熔断阈值"]
REQUIRED_FIELDS = ["策略编号", "策略名称", "触发条件"]
STATUS_ORDER = ["草稿", "待校验", "已启用", "已停用"]
ACTION_RULES = {"提交校验": "待校验", "启用配置": "已启用", "停用配置": "已停用"}
NEGATIVE_ACTIONS = ["停用配置"]


class AntiblockService:
    def list_entries(
        self,
        *,
        filters: dict[str, str] | None = None,
        keyword: str | None = None,
        status: str | None = None,
        page: int = 1,
        size: int = 20,
    ) -> tuple[list[dict[str, Any]], int]:
        rows = store.rows(MODULE)
        for field, expected in (filters or {}).items():
            rows = [row for row in rows if expected.casefold() in str(row.get(field, "")).casefold()]
        if keyword:
            rows = [row for row in rows if keyword.casefold() in str(row.get("策略编号", "")).casefold()]
        if status:
            rows = [row for row in rows if row.get("status") == status]
        total = len(rows)
        start = (page - 1) * size
        return [
            {key: value for key, value in row.items() if not str(key).startswith("_")}
            for row in rows[start:start + size]
        ], total

    def get_entry(self, entry_id: int) -> dict[str, Any] | None:
        return store.find(MODULE, entry_id)

    def create_entry(self, values: dict[str, Any]) -> tuple[dict[str, Any] | None, list[str]]:
        missing = [field for field in REQUIRED_FIELDS if not str(values.get(field) or "").strip()]
        if missing:
            return None, missing
        rows = store.rows(MODULE)
        entry = {"id": max((int(row.get("id", 0)) for row in rows), default=0) + 1}
        entry.update({field: values.get(field) for field in LIST_FIELDS})
        entry["策略编号"] = str(values.get("策略编号") or "").strip()
        entry["延迟范围"] = str(values.get("延迟范围") or "1-3")
        entry["熔断阈值"] = str(values.get("熔断阈值") or "60")
        entry["status"] = STATUS_ORDER[0]
        entry["pending"] = True
        entry["abnormal"] = False
        entry["_版本"] = 1
        rows.append(entry)
        return entry, []

    def run_action(self, entry_id: int, action: str) -> tuple[dict[str, Any] | None, str]:
        entry = store.find(MODULE, entry_id)
        if entry is None:
            return None, f"反爬策略 {entry_id} 不存在或已归档"
        if action not in ACTION_RULES:
            return None, f"动作「{action}」不属于反爬对抗可执行范围"
        target = ACTION_RULES[action]
        if target not in STATUS_ORDER:
            return None, f"目标状态「{target}」不在允许的状态序列里"
        entry["status"] = target
        entry["pending"] = target != STATUS_ORDER[-1]
        entry["abnormal"] = action in NEGATIVE_ACTIONS
        if action == "停用配置":
            risk_service.invalidate_strategy(str(entry.get("策略编号", "")), "策略已停用，不再为新的采集请求生成有效决策")
            return entry, "反爬策略已停用，关联风险决策与代理切换清单同步失效"
        return entry, f"反爬策略已{action}"

    def adjust_threshold(self, entry_id: int, value: Any) -> tuple[dict[str, Any] | None, str]:
        """请求执行中调整熔断阈值：版本递增，旧决策转为待重评，避免下游读到半份规则。"""
        entry = store.find(MODULE, entry_id)
        if entry is None:
            return None, f"反爬策略 {entry_id} 不存在或已归档"
        if entry.get("status") != "已启用":
            return None, f"反爬策略 {entry.get('策略编号')} 当前状态为{entry.get('status')}，不能调整熔断阈值"
        threshold, error = parse_threshold(value)
        if error:
            return None, error
        if str(threshold) == str(entry.get("熔断阈值", "")).strip():
            return None, f"熔断阈值未变化（{threshold}），无需生成新的策略版本"
        previous = str(entry.get("熔断阈值", "")).strip()
        entry["熔断阈值"] = str(threshold)
        entry["_版本"] = int(entry.get("_版本", 1) or 1) + 1
        pending = risk_service.mark_strategy_pending(
            str(entry.get("策略编号", "")),
            f"熔断阈值由 {previous} 调整为 {threshold}，旧决策等待重评",
        )
        return entry, f"熔断阈值已调整为 {threshold}，{pending} 条旧决策转为待重评"

    def get_detail(self, entry_id: int) -> dict[str, Any] | None:
        entry = store.find(MODULE, entry_id)
        if entry is None:
            return None
        return {
            **{key: value for key, value in entry.items() if not str(key).startswith("_")},
            "风险决策": risk_service.strategy_risk(entry),
        }
