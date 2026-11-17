"""代理池业务规则：状态流转、字段校验与筛选口径都收在这里。"""
from __future__ import annotations

from typing import Any

from app.services.risk import DECISION_STATUS_EFFECTIVE, is_expired, now_iso, public
from app.store import store

MODULE = "proxy"
SWITCH_MODULE = "_proxy_switches"
SWITCH_PENDING = "待切换"
SWITCH_DONE = "已切换"
SWITCH_INVALID = "已失效"
PROXY_READY_STATUS = "已启用"
LIST_FIELDS = ["节点编号", "IP地址", "端口号", "协议类型", "匿程度", "响应延迟", "存活检测", "所属区域"]
REQUIRED_FIELDS = ["节点编号", "IP地址", "端口号"]
STATUS_ORDER = ["草稿", "待校验", "已启用", "已停用"]
ACTION_RULES = {"提交校验": "待校验", "启用配置": "已启用", "停用配置": "已停用"}
NEGATIVE_ACTIONS = ["停用配置"]


class ProxyService:
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
            rows = [row for row in rows if keyword.casefold() in str(row.get("节点编号", "")).casefold()]
        if status:
            rows = [row for row in rows if row.get("status") == status]
        total = len(rows)
        start = (page - 1) * size
        return rows[start:start + size], total

    def get_entry(self, entry_id: int) -> dict[str, Any] | None:
        return store.find(MODULE, entry_id)

    def get_switch(self, entry_id: int) -> dict[str, Any] | None:
        row = store.find(SWITCH_MODULE, entry_id)
        return public(row) if row else None

    def create_entry(self, values: dict[str, Any]) -> tuple[dict[str, Any] | None, list[str]]:
        missing = [field for field in REQUIRED_FIELDS if not str(values.get(field) or "").strip()]
        if missing:
            return None, missing
        rows = store.rows(MODULE)
        entry = {"id": max((int(row.get("id", 0)) for row in rows), default=0) + 1}
        entry.update({field: values.get(field) for field in LIST_FIELDS})
        entry["status"] = STATUS_ORDER[0]
        entry["pending"] = True
        entry["abnormal"] = False
        rows.append(entry)
        return entry, []

    def run_action(self, entry_id: int, action: str) -> tuple[dict[str, Any] | None, str]:
        entry = store.find(MODULE, entry_id)
        if entry is None:
            return None, f"代理节点 {entry_id} 不存在或已归档"
        if action not in ACTION_RULES:
            return None, f"动作「{action}」不属于代理池可执行范围"
        target = ACTION_RULES[action]
        if target not in STATUS_ORDER:
            return None, f"目标状态「{target}」不在允许的状态序列里"
        entry["status"] = target
        entry["pending"] = target != STATUS_ORDER[-1]
        entry["abnormal"] = action in NEGATIVE_ACTIONS
        return entry, f"代理节点已{action}"

    # ---------- 风险决策消费与代理切换清单 ----------
    def _ready_nodes(self, region: str) -> list[dict[str, Any]]:
        return [
            row for row in store.rows(MODULE)
            if row.get("status") == PROXY_READY_STATUS and str(row.get("所属区域", "")) == region
        ]

    def _pick_node(self, region: str, excluded: str = "") -> dict[str, Any] | None:
        candidates = [
            row for row in self._ready_nodes(region)
            if str(row.get("节点编号", "")) != excluded
        ]
        if not candidates:
            return None
        return sorted(
            candidates,
            key=lambda row: (
                int("".join(ch for ch in str(row.get("响应延迟", "0")) if ch.isdigit()) or 0),
                int(row.get("id", 0)),
            ),
        )[0]

    def _invalidate_switches(self, decision_code: str, reason: str) -> None:
        for row in store.rows(SWITCH_MODULE):
            if row.get("决策编号") == decision_code and row.get("切换状态") != SWITCH_INVALID:
                row["切换状态"] = SWITCH_INVALID
                row["status"] = SWITCH_INVALID
                row["失效原因"] = reason
                row["最后更新"] = now_iso()

    def switch_list(self) -> list[dict[str, Any]]:
        """代理切换清单：只展示可用于下发的结果，失效决策对应清单一律剔除。"""
        valid: list[dict[str, Any]] = []
        for row in sorted(store.rows(SWITCH_MODULE), key=lambda item: int(item.get("id", 0))):
            if row.get("切换状态") == SWITCH_INVALID:
                continue
            valid.append(public(row))
        return valid

    def build_switches(self, decisions: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        """消费反爬风险决策数据集，按决策的目标区域与熔断状态生成代理切换清单。"""
        source = decisions if decisions is not None else store.rows("_risk_decisions")
        created = skipped = rejected = 0
        messages: list[str] = []
        items: list[dict[str, Any]] = []

        # 只有仍然有效的清单才算“已生成”；失效清单保留历史，但允许按新决策重新生成一份。
        existing = {
            str(row.get("决策编号", "")): row
            for row in store.rows(SWITCH_MODULE)
            if row.get("切换状态") != SWITCH_INVALID
        }
        for decision in source:
            code = str(decision.get("决策编号", ""))
            if not code:
                rejected += 1
                messages.append("决策缺少决策编号，代理池拒绝生成切换结果")
                continue
            if decision.get("决策状态") != DECISION_STATUS_EFFECTIVE or is_expired(decision):
                skipped += 1
                messages.append(f"{code} 不是有效决策，代理池不生成切换结果")
                continue
            if code in existing:
                rejected += 1
                messages.append(f"{code} 已存在代理切换结果，拒绝重复生成")
                continue

            region = str(decision.get("目标区域", "")).strip()
            circuit = str(decision.get("熔断状态", ""))
            current = str(decision.get("当前代理", "")).strip()
            if circuit == "已熔断":
                node = self._pick_node(region, excluded=current)
                if node is None:
                    rejected += 1
                    messages.append(f"{code} 目标区域「{region}」没有可用代理节点，拒绝生成切换清单")
                    continue
                switch_type = "熔断切换"
                action = f"停用 {current or '当前代理'}，切换至 {node.get('节点编号')}"
            else:
                node = None
                switch_type = "保持出口"
                action = "维持当前代理，仅按决策补充延迟与UA伪装"

            rows = store.rows(SWITCH_MODULE)
            entry = {
                "id": max((int(row.get("id", 0)) for row in rows), default=0) + 1,
                "status": SWITCH_PENDING,
                "pending": True,
                "abnormal": circuit == "已熔断",
                "清单编号": f"SWIT-{len(rows) + 1:04d}",
                "决策编号": code,
                "请求标识": decision.get("请求标识"),
                "策略编号": decision.get("策略编号"),
                "策略版本": decision.get("策略版本"),
                "目标区域": region,
                "熔断状态": circuit,
                "切换类型": switch_type,
                "当前代理": current,
                "切换代理": node.get("节点编号") if node else current,
                "切换动作": action,
                "切换状态": SWITCH_PENDING,
                "决策生效边界": decision.get("生效边界"),
                "最后更新": now_iso(),
            }
            rows.append(entry)
            existing[code] = entry
            created += 1
            items.append(public(entry))

        return {
            "ok": created > 0,
            "message": f"代理切换清单已生成：新增 {created} 条，跳过 {skipped} 条，拒绝 {rejected} 条",
            "created": created,
            "skipped": skipped,
            "rejected": rejected,
            "messages": messages,
            "items": items,
        }

    def run_switch(self, entry_id: int) -> tuple[dict[str, Any] | None, str]:
        entry = store.find(SWITCH_MODULE, entry_id)
        if entry is None:
            return None, f"代理切换清单 {entry_id} 不存在或已归档"
        if entry.get("切换状态") == SWITCH_INVALID:
            return None, f"清单 {entry.get('清单编号')} 关联的决策已失效，代理池拒绝执行切换"
        if entry.get("切换状态") == SWITCH_DONE:
            return None, f"清单 {entry.get('清单编号')} 已执行过切换，拒绝重复下发"
        decision = None
        for row in store.rows("_risk_decisions"):
            if row.get("决策编号") == entry.get("决策编号"):
                decision = row
                break
        if decision is None or decision.get("决策状态") != DECISION_STATUS_EFFECTIVE or is_expired(decision):
            entry["切换状态"] = SWITCH_INVALID
            entry["status"] = SWITCH_INVALID
            entry["失效原因"] = "关联决策已失效或超出生效边界"
            return None, f"清单 {entry.get('清单编号')} 关联的决策已失效，代理池拒绝执行切换"
        if entry.get("切换类型") == "熔断切换":
            target = str(entry.get("切换代理", "")).strip()
            nodes = [row for row in self._ready_nodes(str(entry.get("目标区域", ""))) if str(row.get("节点编号", "")) == target]
            if not nodes:
                entry["切换状态"] = SWITCH_INVALID
                entry["status"] = SWITCH_INVALID
                entry["失效原因"] = f"目标区域「{entry.get('目标区域')}」的代理 {target} 不可用"
                return None, f"目标区域「{entry.get('目标区域')}」的代理 {target} 不可用，拒绝切换"
        entry["切换状态"] = SWITCH_DONE
        entry["status"] = SWITCH_DONE
        entry["pending"] = False
        return entry, f"代理切换已执行：{entry.get('切换动作')}"
