"""反爬风险决策业务规则。

反爬对抗在采集请求执行前，根据请求结果（状态码、耗时、验证码、封禁、连续失败）
计算风险评分，并选择一条可执行策略：维持访问 / 降速伪装 / 熔断切换。

决策数据集的三条硬约束：
1. 决策必须引用当时的触发条件与策略版本，阈值和延迟范围按反爬对抗核定标准校验；
2. 同一请求标识只保留一条最终决策，重复送交只增加计数、不再写入新记录；
3. 策略停用或阈值调整后，旧决策不再作为有效决策下发给代理池。
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta
from typing import Any

from app.store import store

DECISION_MODULE = "_risk_decisions"
SWITCH_MODULE = "_proxy_switches"
STRATEGY_MODULE = "antiblock"

# 反爬对抗核定的判定标准：评分、熔断阈值、延迟范围都有明确上下界。
SCORE_MIN = 0
SCORE_MAX = 100
THRESHOLD_MIN = 1
THRESHOLD_MAX = 100
DELAY_MIN_SECONDS = 0
DELAY_MAX_SECONDS = 60
EFFECTIVE_SECONDS = 300

DECISION_STATUS_EFFECTIVE = "已生效"
DECISION_STATUS_PENDING = "待重评"
DECISION_STATUS_INVALID = "已失效"
DECISION_STATUS_REJECTED = "已拒绝"
CIRCUIT_OPEN = "已熔断"
CIRCUIT_CLOSED = "未熔断"


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def public(row: dict[str, Any]) -> dict[str, Any]:
    """内部字段以下划线开头，只用于去重和计算，不进入页面契约。"""
    return {key: value for key, value in row.items() if not str(key).startswith("_")}


def _get(payload: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in payload and payload[key] not in (None, ""):
            return payload[key]
    return None


def _to_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().casefold() in {"是", "true", "1", "yes", "on", "触发"}


def _to_int(value: Any, default: int | None = None) -> int | None:
    if value is None or str(value).strip() == "":
        return default
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _numbers(text: Any) -> list[int]:
    return [int(item) for item in re.findall(r"\d+", str(text or ""))]


def parse_threshold(text: Any) -> tuple[int, str]:
    """熔断阈值取策略里的第一个数字；未配置时沿用默认 60。"""
    values = _numbers(text)
    if not values:
        return 60, ""
    value = values[0]
    if value < THRESHOLD_MIN or value > THRESHOLD_MAX:
        return value, f"熔断阈值 {value} 超出反爬对抗核定范围 {THRESHOLD_MIN}-{THRESHOLD_MAX}"
    return value, ""


def parse_delay(text: Any) -> tuple[tuple[int, int], str]:
    """延迟范围支持 "1-3" 秒；未配置时沿用默认 1-3 秒。"""
    values = _numbers(text)
    if not values:
        return (1, 3), ""
    low = values[0]
    high = values[1] if len(values) > 1 else values[0]
    if low < DELAY_MIN_SECONDS or high > DELAY_MAX_SECONDS or low > high:
        return (low, high), (
            f"延迟范围 {low}-{high} 不符合反爬对抗核定范围 "
            f"{DELAY_MIN_SECONDS}-{DELAY_MAX_SECONDS} 秒且需下界不大于上界"
        )
    return (low, high), ""


def strategy_version(strategy: dict[str, Any]) -> str:
    return f"v{int(strategy.get('_版本', 1) or 1)}"


def _strategy_by_code(code: str) -> dict[str, Any] | None:
    for row in store.rows(STRATEGY_MODULE):
        if str(row.get("策略编号", "")).casefold() == code.casefold():
            return row
    return None


def is_expired(row: dict[str, Any]) -> bool:
    """生效终点已过期的决策不能再下发给采集请求。"""
    end = str(row.get("生效终点", "")).strip()
    if not end:
        return False
    try:
        return datetime.fromisoformat(end) <= datetime.now().astimezone()
    except ValueError:
        return False


def _decision_by_request(request_id: str) -> dict[str, Any] | None:
    for row in store.rows(DECISION_MODULE):
        if str(row.get("请求标识", "")).casefold() == request_id.casefold():
            return row
    return None


def _invalidate_switches(decision_id: Any, reason: str) -> None:
    for row in store.rows(SWITCH_MODULE):
        if row.get("决策编号") == decision_id and row.get("切换状态") != "已失效":
            row["切换状态"] = "已失效"
            row["status"] = "已失效"
            row["失效原因"] = reason


def _decision_id(rows: list[dict[str, Any]]) -> int:
    return max((int(row.get("id", 0)) for row in rows), default=0) + 1


def _effective_range(
    seconds: int = EFFECTIVE_SECONDS,
    after: str = "",
) -> tuple[str, str, str]:
    """生效边界从当前时刻开始；规则冲突时保证新边界晚于旧边界。"""
    start = datetime.now().astimezone().replace(microsecond=0)
    if after:
        try:
            previous = datetime.fromisoformat(after)
            if start <= previous:
                start = previous + timedelta(seconds=1)
        except ValueError:
            pass
    end = start + timedelta(seconds=seconds)
    start_text = start.isoformat(timespec="seconds")
    end_text = end.isoformat(timespec="seconds")
    return start_text, end_text, f"{start_text} ~ {end_text}"


class RiskService:
    # ---------- 判定标准 ----------
    def criteria(self) -> dict[str, Any]:
        return {
            "判定标准": [
                {"判定项": "风险评分", "下限": SCORE_MIN, "上限": SCORE_MAX, "说明": "请求结果计算出的风险分"},
                {"判定项": "熔断阈值", "下限": THRESHOLD_MIN, "上限": THRESHOLD_MAX, "说明": "策略配置的熔断阈值"},
                {"判定项": "延迟范围", "下限": DELAY_MIN_SECONDS, "上限": DELAY_MAX_SECONDS, "说明": "单位秒，下界不得大于上界"},
            ],
            "必需字段": ["请求标识", "策略编号"],
            "生效时长秒": EFFECTIVE_SECONDS,
            "核定方": "反爬对抗",
            "判定规则": "阈值与范围均在核定区间内才允许生成风险决策，否则拒绝。",
        }

    # ---------- 风险评分 ----------
    def _score(self, payload: dict[str, Any]) -> tuple[int, list[str], dict[str, Any]]:
        score = 10
        hits: list[str] = []

        status_code = _to_int(_get(payload, "响应状态码", "status_code", "statusCode"), 200)
        response_time = _to_int(_get(payload, "响应耗时", "响应耗时毫秒", "response_time_ms", "responseTime"), 0)
        captcha = _to_bool(_get(payload, "触发验证码", "验证码", "captcha"))
        blocked = _to_bool(_get(payload, "触发封禁", "封禁", "blocked"))
        failures = _to_int(_get(payload, "连续失败次数", "consecutive_failures", "failures"), 0) or 0

        if blocked:
            score += 55
            hits.append("触发IP封禁")
        if captcha:
            score += 35
            hits.append("命中验证码挑战")
        if status_code == 403:
            score += 50
            hits.append("响应状态 403（拒绝访问）")
        elif status_code == 429:
            score += 45
            hits.append("响应状态 429（触发限流）")
        elif status_code and 500 <= status_code < 600:
            score += 20
            hits.append(f"响应状态 {status_code}（服务异常）")
        if response_time >= 5000:
            score += 20
            hits.append("响应耗时超过 5000ms")
        elif response_time >= 2000:
            score += 10
            hits.append("响应耗时超过 2000ms")
        if failures > 0:
            score += min(25, failures * 5)
            hits.append(f"连续失败 {failures} 次")

        score = max(SCORE_MIN, min(SCORE_MAX, score))
        return score, (hits or ["未命中异常特征"]), {
            "status_code": status_code,
            "response_time": response_time,
            "captcha": captcha,
            "blocked": blocked,
            "failures": failures,
        }

    def _resolve_strategy(self, payload: dict[str, Any]) -> tuple[dict[str, Any] | None, str]:
        strategy_id = _to_int(_get(payload, "策略ID", "strategy_id", "strategyId"))
        if strategy_id is not None:
            row = store.find(STRATEGY_MODULE, strategy_id)
            return row, "" if row else f"反爬策略 {strategy_id} 不存在或已归档"
        code = str(_get(payload, "策略编号", "strategy_code", "strategyCode") or "").strip()
        if not code:
            return None, "缺少必填字段：策略编号"
        row = _strategy_by_code(code)
        return row, "" if row else f"反爬策略 {code} 不存在或已归档"

    def _target_region(self, payload: dict[str, Any], strategy: dict[str, Any]) -> str:
        region = str(_get(payload, "目标区域", "region", "target_region") or "").strip()
        if region:
            return region
        match = re.search(r"区域\s*[=:：]\s*([^\s,，;；]+)", str(strategy.get("触发条件", "")))
        if match:
            return match.group(1)
        return "默认区域"

    def _compose(
        self,
        *,
        strategy: dict[str, Any],
        request_id: str,
        score: int,
        hits: list[str],
        threshold: int,
        delay: tuple[int, int],
        region: str,
        current_proxy: str,
        signature: str,
        version: str,
        start: str,
        end: str,
        boundary: str,
        conflict: str,
        previous_boundary: str,
        repeat_count: int,
    ) -> dict[str, Any]:
        circuit = score >= threshold
        if circuit:
            decision_name = "熔断切换"
            circuit_status = CIRCUIT_OPEN
            suggestion = f"熔断当前出口，切换至「{region}」区域代理后再发起请求"
        elif score >= max(1, int(threshold * 0.6)):
            decision_name = "降速伪装"
            circuit_status = CIRCUIT_CLOSED
            suggestion = "保持当前代理，追加随机延迟并按策略轮换UA伪装"
        else:
            decision_name = "维持访问"
            circuit_status = CIRCUIT_CLOSED
            suggestion = "风险可控，无需切换代理，按原策略继续访问"

        return {
            # 既有反爬策略字段沿用原字段名，方便页面与导出对齐。
            "策略编号": strategy.get("策略编号"),
            "策略名称": strategy.get("策略名称"),
            "触发条件": strategy.get("触发条件"),
            "延迟范围": strategy.get("延迟范围"),
            "UA伪装": strategy.get("UA伪装"),
            "Referer生成": strategy.get("Referer生成"),
            "Cookie策略": strategy.get("Cookie策略"),
            "熔断阈值": strategy.get("熔断阈值"),
            # 以下为反爬风险决策数据集新增字段，只追加。
            "决策编号": "",
            "请求标识": request_id,
            "策略版本": version,
            "风险评分": score,
            "命中条件": "；".join(hits),
            "决策策略": decision_name,
            "目标区域": region,
            "当前代理": current_proxy,
            "熔断状态": circuit_status,
            "代理切换建议": suggestion,
            "生效起点": start,
            "生效终点": end,
            "生效边界": boundary,
            "上一生效边界": previous_boundary,
            "判定结果": "通过",
            "判定说明": "熔断阈值与延迟范围符合反爬对抗核定标准",
            "决策状态": DECISION_STATUS_EFFECTIVE,
            "规则冲突": conflict,
            "重复送交次数": repeat_count,
            "最后更新": now_iso(),
            "_判定签名": signature,
            "_熔断阈值数值": threshold,
            "_延迟下界": delay[0],
            "_延迟上界": delay[1],
        }

    # ---------- 风险评估与写入 ----------
    def assess(self, payload: dict[str, Any]) -> tuple[dict[str, Any] | None, str, str]:
        """返回 (决策, 说明, 结果)。结果取 created / updated / duplicate / rejected。"""
        request_id = str(_get(payload, "请求标识", "request_id", "requestId") or "").strip()
        if not request_id:
            return None, "缺少必填字段：请求标识", "rejected"

        strategy, error = self._resolve_strategy(payload)
        if strategy is None:
            return None, error, "rejected"
        if strategy.get("status") != "已启用":
            self.invalidate_strategy(str(strategy.get("策略编号", "")), "策略已停用，不再生成新的有效决策")
            return None, f"反爬策略 {strategy.get('策略编号')} 当前状态为{strategy.get('status')}，不能生成有效风险决策", "rejected"

        threshold, threshold_error = parse_threshold(strategy.get("熔断阈值"))
        if threshold_error:
            return None, threshold_error, "rejected"
        delay, delay_error = parse_delay(strategy.get("延迟范围"))
        if delay_error:
            return None, delay_error, "rejected"

        score, hits, _ = self._score(payload)
        status_code = _to_int(_get(payload, "响应状态码", "status_code", "statusCode"), 200)
        if status_code is None:
            return None, "响应状态码必须是整数", "rejected"
        response_time = _to_int(_get(payload, "响应耗时", "响应耗时毫秒", "response_time_ms", "responseTime"), 0)
        if response_time is None or response_time < 0:
            return None, "响应耗时必须是非负整数", "rejected"
        failures = _to_int(_get(payload, "连续失败次数", "consecutive_failures", "failures"), 0)
        if failures is None or failures < 0:
            return None, "连续失败次数必须是非负整数", "rejected"

        region = self._target_region(payload, strategy)
        current_proxy = str(_get(payload, "当前代理", "current_proxy", "currentProxy") or "").strip()
        version = strategy_version(strategy)
        previous = _decision_by_request(request_id)
        start, end, boundary = _effective_range(after=str((previous or {}).get("生效起点", "")))
        signature = json.dumps(
            {
                "请求标识": request_id,
                "策略编号": strategy.get("策略编号"),
                "策略版本": version,
                "响应状态码": status_code,
                "响应耗时": response_time,
                "触发封禁": _to_bool(_get(payload, "触发封禁", "封禁", "blocked")),
                "触发验证码": _to_bool(_get(payload, "触发验证码", "验证码", "captcha")),
                "连续失败次数": failures,
                "目标区域": region,
                "当前代理": current_proxy,
            },
            ensure_ascii=False,
            sort_keys=True,
        )

        rows = store.rows(DECISION_MODULE)
        existing = _decision_by_request(request_id)

        if existing is None:
            entry = {
                "id": _decision_id(rows),
                "status": DECISION_STATUS_EFFECTIVE,
                "pending": False,
                "abnormal": score >= threshold,
            }
            entry.update(self._compose(
                strategy=strategy,
                request_id=request_id,
                score=score,
                hits=hits,
                threshold=threshold,
                delay=delay,
                region=region,
                current_proxy=current_proxy,
                signature=signature,
                version=version,
                start=start,
                end=end,
                boundary=boundary,
                conflict="否",
                previous_boundary="",
                repeat_count=0,
            ))
            entry["决策编号"] = f"RISK-{int(entry['id']):04d}"
            rows.append(entry)
            return public(entry), "反爬风险决策已生成并写入数据集", "created"

        # 同一请求标识只保留一条最终决策；重试只累计送交次数。
        same_rule = (
            str(existing.get("策略编号", "")).casefold() == str(strategy.get("策略编号", "")).casefold()
            and existing.get("策略版本") == version
        )
        same_result = existing.get("_判定签名") == signature
        if (
            same_rule
            and same_result
            and existing.get("决策状态") == DECISION_STATUS_EFFECTIVE
            and not is_expired(existing)
        ):
            existing["重复送交次数"] = int(existing.get("重复送交次数", 0) or 0) + 1
            existing["最后更新"] = now_iso()
            existing["决策状态"] = DECISION_STATUS_EFFECTIVE
            return (
                public(existing),
                "反爬对抗拒绝重复写入：该请求已存在唯一最终风险决策，未产生并行决策",
                "duplicate",
            )

        # 策略版本或策略编号发生变化：旧决策与新规则冲突，用一份带生效边界的新决策覆盖。
        previous_boundary = str(existing.get("生效边界", ""))
        old_decision_code = existing.get("决策编号")
        existing.update(self._compose(
            strategy=strategy,
            request_id=request_id,
            score=score,
            hits=hits,
            threshold=threshold,
            delay=delay,
            region=region,
            current_proxy=current_proxy,
            signature=signature,
            version=version,
            start=start,
            end=end,
            boundary=boundary,
            conflict="是" if not same_rule else "否",
            previous_boundary=previous_boundary,
            repeat_count=int(existing.get("重复送交次数", 0) or 0) + 1,
        ))
        existing["决策编号"] = old_decision_code
        existing["status"] = DECISION_STATUS_EFFECTIVE
        existing["abnormal"] = score >= threshold
        if same_rule:
            existing["规则冲突"] = "否"
            existing["策略版本"] = version
        _invalidate_switches(
            old_decision_code,
            "策略版本变更，旧生效边界失效" if not same_rule else "请求结果变化，旧切换清单失效",
        )
        if same_rule:
            message = "请求结果发生变化，同一请求标识仅保留这一份最新风险决策，旧代理切换清单已失效"
        else:
            message = "熔断阈值或策略版本已调整，规则冲突已合并：下游只应用这一份带生效边界的决策"
        return public(existing), message, "updated"

    def submit_batch(self, items: list[dict[str, Any]]) -> dict[str, Any]:
        if not items:
            return {"ok": False, "message": "风险决策数据集为空，拒绝写入", "created": 0, "duplicates": 0, "rejected": 0, "items": []}
        result_items: list[dict[str, Any]] = []
        created = duplicates = rejected = 0
        for item in items:
            entry, message, outcome = self.assess(item if isinstance(item, dict) else {})
            if outcome == "created":
                created += 1
            elif outcome == "updated":
                created += 1
            elif outcome == "duplicate":
                duplicates += 1
            else:
                rejected += 1
            result_items.append({
                "ok": outcome != "rejected",
                "outcome": outcome,
                "message": message,
                "entry": entry,
            })
        ok = created > 0 or duplicates > 0
        return {
            "ok": ok,
            "message": f"数据集已处理：写入 {created} 条，拒绝重复 {duplicates} 条，拒绝 {rejected} 条",
            "created": created,
            "duplicates": duplicates,
            "rejected": rejected,
            "items": result_items,
        }

    # ---------- 查询 ----------
    def list_decisions(
        self,
        *,
        filters: dict[str, str] | None = None,
        keyword: str | None = None,
        status: str | None = None,
        page: int = 1,
        size: int = 20,
    ) -> tuple[list[dict[str, Any]], int]:
        rows = store.rows(DECISION_MODULE)
        for field, expected in (filters or {}).items():
            rows = [row for row in rows if expected.casefold() in str(row.get(field, "")).casefold()]
        if keyword:
            rows = [
                row for row in rows
                if keyword.casefold() in str(row.get("决策编号", "")).casefold()
                or keyword.casefold() in str(row.get("请求标识", "")).casefold()
            ]
        if status:
            rows = [row for row in rows if row.get("决策状态") == status]
        ordered = sorted(rows, key=lambda row: int(row.get("id", 0)))
        total = len(ordered)
        start = (page - 1) * size
        return [public(row) for row in ordered[start:start + size]], total

    def get_decision(self, decision_id: int) -> dict[str, Any] | None:
        row = store.find(DECISION_MODULE, decision_id)
        return public(row) if row else None

    def summary(self) -> dict[str, Any]:
        rows = store.rows(DECISION_MODULE)
        return {
            "决策总数": len(rows),
            "有效决策数": sum(1 for row in rows if row.get("决策状态") == DECISION_STATUS_EFFECTIVE),
            "熔断决策数": sum(1 for row in rows if row.get("决策状态") == DECISION_STATUS_EFFECTIVE and row.get("熔断状态") == CIRCUIT_OPEN),
            "重复送交次数": sum(int(row.get("重复送交次数", 0) or 0) for row in rows),
            "待重评决策数": sum(1 for row in rows if row.get("决策状态") == DECISION_STATUS_PENDING),
        }

    def strategy_risk(self, strategy: dict[str, Any]) -> dict[str, Any]:
        code = str(strategy.get("策略编号", ""))
        decisions = [row for row in store.rows(DECISION_MODULE) if str(row.get("策略编号", "")).casefold() == code.casefold()]
        latest = max(decisions, key=lambda row: int(row.get("id", 0)), default=None)
        valid = [row for row in decisions if row.get("决策状态") == DECISION_STATUS_EFFECTIVE]
        requests: dict[str, int] = {}
        for row in decisions:
            key = str(row.get("请求标识", ""))
            requests[key] = requests.get(key, 0) + 1
        check = [
            {"请求标识": key, "决策数": count, "有效决策数": sum(
                1 for row in decisions
                if str(row.get("请求标识", "")) == key and row.get("决策状态") == DECISION_STATUS_EFFECTIVE
            )}
            for key, count in sorted(requests.items())
        ]
        threshold, _ = parse_threshold(strategy.get("熔断阈值"))
        return {
            "策略编号": code,
            "策略名称": strategy.get("策略名称"),
            "策略版本": strategy_version(strategy),
            "触发条件": strategy.get("触发条件"),
            "延迟范围": strategy.get("延迟范围"),
            "UA伪装": strategy.get("UA伪装"),
            "熔断阈值": strategy.get("熔断阈值"),
            "风险评分": int(latest.get("风险评分", 0)) if latest else 0,
            "命中条件": latest.get("命中条件", "暂无风险评估记录") if latest else "暂无风险评估记录",
            "代理切换建议": latest.get("代理切换建议", "") if latest else (
                f"风险评分达到 {threshold} 时触发熔断并切换代理" if threshold else "等待请求结果评估"
            ),
            "决策数量": len(decisions),
            "有效决策数": len(valid),
            "重复送交次数": sum(int(row.get("重复送交次数", 0) or 0) for row in decisions),
            "请求核对": check,
            "最近决策": public(latest) if latest else None,
        }

    def invalidate_strategy(self, code: str, reason: str) -> int:
        """策略停用后，旧决策与旧切换清单都不能继续作为有效结果。"""
        changed = 0
        for row in store.rows(DECISION_MODULE):
            if str(row.get("策略编号", "")).casefold() != code.casefold():
                continue
            if row.get("决策状态") != DECISION_STATUS_INVALID:
                row["决策状态"] = DECISION_STATUS_INVALID
                row["判定结果"] = "失效"
                row["判定说明"] = reason
                row["最后更新"] = now_iso()
                row["status"] = DECISION_STATUS_INVALID
                row["abnormal"] = True
                changed += 1
            _invalidate_switches(row.get("决策编号"), reason)
        return changed

    def mark_strategy_pending(self, code: str, reason: str) -> int:
        """阈值调整时旧决策先挂起，等同一请求重新评估后只保留一份新决策。"""
        changed = 0
        for row in store.rows(DECISION_MODULE):
            if str(row.get("策略编号", "")).casefold() != code.casefold():
                continue
            if row.get("决策状态") == DECISION_STATUS_INVALID:
                continue
            row["决策状态"] = DECISION_STATUS_PENDING
            row["规则冲突"] = "是"
            row["判定说明"] = reason
            row["最后更新"] = now_iso()
            row["status"] = DECISION_STATUS_PENDING
            changed += 1
            _invalidate_switches(row.get("决策编号"), reason)
        return changed


risk_service = RiskService()
