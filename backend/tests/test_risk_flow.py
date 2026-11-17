"""反爬风险决策与代理切换清单的规则回归测试。

直接调用 service 层，不依赖 HTTP 测试客户端；每个用例前把内存仓库恢复成种子数据。
"""
from __future__ import annotations

import copy
import unittest

from app.seed import SEED_ROWS
from app.services.antiblock import AntiblockService
from app.services.proxy import ProxyService
from app.services.risk import DECISION_MODULE, SWITCH_MODULE, risk_service
from app.store import Store, store


def reset_store() -> None:
    store._tables = {name: [copy.deepcopy(row) for row in rows] for name, rows in SEED_ROWS.items()}
    store._tables[DECISION_MODULE] = []
    store._tables[SWITCH_MODULE] = []


def enable_proxy(entry_id: int) -> None:
    service = ProxyService()
    service.run_action(entry_id, "提交校验")
    service.run_action(entry_id, "启用配置")


class RiskDecisionTest(unittest.TestCase):
    def setUp(self) -> None:
        reset_store()
        self.antiblock = AntiblockService()
        self.proxy = ProxyService()

    def request(self, request_id: str = "REQ-1", **extra: object) -> dict[str, object]:
        payload: dict[str, object] = {
            "请求标识": request_id,
            "策略编号": "ANTI-0003",
            "响应状态码": 403,
            "响应耗时": 3200,
            "连续失败次数": 3,
            "目标区域": "华东",
        }
        payload.update(extra)
        return payload

    def test_duplicate_request_keeps_single_decision(self) -> None:
        first, _, outcome = risk_service.assess(self.request())
        second, message, repeated = risk_service.assess(self.request())
        self.assertEqual(outcome, "created")
        self.assertEqual(repeated, "duplicate")
        self.assertIn("拒绝重复写入", message)
        self.assertEqual(first["决策编号"], second["决策编号"])
        self.assertEqual(len(store.rows(DECISION_MODULE)), 1)

    def test_decision_references_trigger_and_version(self) -> None:
        entry, _, _ = risk_service.assess(self.request())
        self.assertEqual(entry["触发条件"], "响应状态码=403 或 连续失败次数>=3；区域=华东")
        self.assertEqual(entry["策略版本"], "v1")
        self.assertGreaterEqual(int(entry["风险评分"]), int(entry["熔断阈值"]))
        self.assertEqual(entry["熔断状态"], "已熔断")
        self.assertTrue(entry["生效边界"])

    def test_disabled_strategy_rejects_new_requests(self) -> None:
        self.antiblock.run_action(3, "停用配置")
        entry, message, outcome = risk_service.assess(self.request("REQ-9"))
        self.assertIsNone(entry)
        self.assertEqual(outcome, "rejected")
        self.assertIn("不能生成有效风险决策", message)

    def test_disabling_strategy_invalidates_old_decision(self) -> None:
        risk_service.assess(self.request())
        self.antiblock.run_action(3, "停用配置")
        rows = store.rows(DECISION_MODULE)
        self.assertEqual(rows[0]["决策状态"], "已失效")

    def test_out_of_range_threshold_is_rejected(self) -> None:
        store.find("antiblock", 3)["熔断阈值"] = "300"
        entry, message, outcome = risk_service.assess(self.request())
        self.assertIsNone(entry)
        self.assertEqual(outcome, "rejected")
        self.assertIn("超出反爬对抗核定范围", message)

    def test_threshold_conflict_yields_one_complete_decision(self) -> None:
        risk_service.assess(self.request())
        _, message = self.antiblock.adjust_threshold(3, "75")
        self.assertIn("待重评", message)
        updated, _, outcome = risk_service.assess(self.request())
        self.assertEqual(outcome, "updated")
        self.assertEqual(len(store.rows(DECISION_MODULE)), 1)
        self.assertEqual(updated["策略版本"], "v2")
        self.assertEqual(updated["熔断阈值"], "75")
        self.assertTrue(updated["上一生效边界"])
        self.assertGreater(updated["生效起点"], updated["上一生效边界"].split(" ~ ")[0])

    def test_dataset_batch_writes_one_copy(self) -> None:
        payload = self.request("REQ-BATCH")
        result = risk_service.submit_batch([payload, dict(payload)])
        self.assertTrue(result["ok"])
        self.assertEqual(result["created"], 1)
        self.assertEqual(result["duplicates"], 1)
        self.assertEqual(len(store.rows(DECISION_MODULE)), 1)

    def test_empty_dataset_is_rejected(self) -> None:
        result = risk_service.submit_batch([])
        self.assertFalse(result["ok"])
        self.assertEqual(store.rows(DECISION_MODULE), [])


class ProxySwitchTest(unittest.TestCase):
    def setUp(self) -> None:
        reset_store()
        self.antiblock = AntiblockService()
        self.proxy = ProxyService()
        enable_proxy(1)
        enable_proxy(2)
        enable_proxy(3)

    def decision(self, request_id: str = "REQ-S", region: str = "华东") -> dict[str, object]:
        entry, _, _ = risk_service.assess({
            "请求标识": request_id,
            "策略编号": "ANTI-0003",
            "响应状态码": 403,
            "响应耗时": 3200,
            "目标区域": region,
        })
        self.assertIsNotNone(entry)
        return dict(entry or {})

    def test_switch_respects_target_region(self) -> None:
        self.decision(region="华南")
        result = self.proxy.build_switches()
        self.assertEqual(result["created"], 1)
        item = result["items"][0]
        self.assertEqual(item["目标区域"], "华南")
        self.assertEqual(item["切换代理"], "PROX-0002")
        self.assertEqual(item["切换类型"], "熔断切换")

    def test_region_without_proxy_is_rejected(self) -> None:
        self.decision(region="西北")
        result = self.proxy.build_switches()
        self.assertEqual(result["created"], 0)
        self.assertEqual(result["rejected"], 1)
        self.assertIn("没有可用代理节点", result["messages"][0])

    def test_rebuild_is_idempotent(self) -> None:
        self.decision()
        first = self.proxy.build_switches()
        second = self.proxy.build_switches()
        self.assertEqual(first["created"], 1)
        self.assertEqual(second["created"], 0)
        self.assertEqual(second["rejected"], 1)
        self.assertEqual(len(store.rows(SWITCH_MODULE)), 1)

    def test_invalid_decision_is_skipped(self) -> None:
        self.decision()
        self.antiblock.run_action(3, "停用配置")
        result = self.proxy.build_switches()
        self.assertEqual(result["created"], 0)
        self.assertEqual(result["skipped"], 1)

    def test_switch_cannot_apply_after_threshold_change(self) -> None:
        self.decision()
        self.proxy.build_switches()
        switch = store.rows(SWITCH_MODULE)[0]
        self.antiblock.adjust_threshold(3, "75")
        entry, message = self.proxy.run_switch(int(switch["id"]))
        self.assertIsNone(entry)
        self.assertIn("关联的决策已失效", message)

    def test_switch_apply_only_once(self) -> None:
        self.decision()
        self.proxy.build_switches()
        switch = store.rows(SWITCH_MODULE)[0]
        entry, _ = self.proxy.run_switch(int(switch["id"]))
        self.assertIsNotNone(entry)
        again, message = self.proxy.run_switch(int(switch["id"]))
        self.assertIsNone(again)
        self.assertIn("拒绝重复下发", message)


if __name__ == "__main__":
    unittest.main()
