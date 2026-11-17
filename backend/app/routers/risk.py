"""反爬风险决策数据集接口。

反爬对抗负责核定判定标准；只有阈值与范围满足标准的请求结果才允许写入数据集。
同一请求标识重复送交不会产生第二条决策，数据集只保留一份带生效边界的最终决策。
"""
from __future__ import annotations

import csv
import io
from typing import Any

from fastapi import APIRouter, Body, HTTPException, Query, Request
from fastapi.responses import StreamingResponse

from app.schemas import PageResult
from app.services.risk import (
    DECISION_STATUS_EFFECTIVE,
    DECISION_STATUS_INVALID,
    DECISION_STATUS_PENDING,
    risk_service,
)

router = APIRouter(prefix="/api/risk", tags=["反爬风险决策"])

service = risk_service

LIST_FIELDS = [
    "决策编号", "请求标识", "策略编号", "策略版本", "风险评分", "命中条件",
    "决策策略", "熔断状态", "目标区域", "代理切换建议", "判定结果", "决策状态",
]
STATUSES = [DECISION_STATUS_EFFECTIVE, DECISION_STATUS_PENDING, DECISION_STATUS_INVALID]


def query_filters(request: Request) -> dict[str, str]:
    return {
        key: value.strip()
        for key, value in request.query_params.items()
        if key in LIST_FIELDS and value.strip()
    }


@router.get("/criteria", response_model=dict)
def get_criteria() -> dict[str, Any]:
    """反爬对抗核定的判定标准：页面据此展示阈值与范围的允许区间。"""
    return service.criteria()


@router.get("/summary", response_model=dict)
def get_summary() -> dict[str, Any]:
    return service.summary()


@router.get("", response_model=PageResult[dict])
def list_decisions(
    request: Request,
    keyword: str | None = Query(default=None, description="按决策编号或请求标识检索"),
    status: str | None = Query(default=None, description="已生效、待重评、已失效"),
    page: int = Query(default=1, ge=1),
    size: int = Query(default=50, ge=1, le=200),
) -> PageResult[dict]:
    items, total = service.list_decisions(
        filters=query_filters(request), keyword=keyword, status=status, page=page, size=size)
    return PageResult(items=items, total=total, page=page, size=size)


@router.get("/export")
def export_decisions(
    request: Request,
    keyword: str | None = Query(default=None),
    status: str | None = Query(default=None),
) -> StreamingResponse:
    """导出当前筛选条件下的决策数据集；必须声明在 /{decision_id} 之前。"""
    items, _ = service.list_decisions(
        filters=query_filters(request), keyword=keyword, status=status, page=1, size=1000000)
    output = io.StringIO()
    output.write("﻿")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(["id", *LIST_FIELDS, "生效边界"])
    for item in items:
        row = []
        for value in [item.get("id"), *(item.get(field, "") for field in LIST_FIELDS), item.get("生效边界", "")]:
            text = "" if value is None else str(value)
            row.append("'" + text if text.startswith(("=", "+", "-", "@")) else text)
        writer.writerow(row)
    return StreamingResponse(
        iter([output.getvalue()]), media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="risk.csv"'})


@router.post("/assess", response_model=dict)
def assess(payload: dict[str, Any]) -> dict[str, Any]:
    """对一次采集请求结果做风险评估；重复请求只更新重复次数，不新增决策。"""
    entry, message, outcome = service.assess(payload)
    return {
        "ok": outcome != "rejected",
        "outcome": outcome,
        "message": message,
        "entry": entry,
    }


@router.post("/dataset", response_model=dict)
def submit_dataset(payload: Any = Body(default=None)) -> dict[str, Any]:
    """批量送交风险决策数据集：空集拒绝，重复项只写入一份。"""
    if isinstance(payload, list):
        items = payload
    elif isinstance(payload, dict):
        raw = payload.get("items") or payload.get("records") or payload.get("数据集")
        items = raw if isinstance(raw, list) else []
    else:
        items = []
    result = service.submit_batch([item for item in items if isinstance(item, dict)])
    return {**result, "ok": bool(result.get("ok")) and result.get("rejected", 0) == 0}


@router.get("/{decision_id}", response_model=dict)
def get_decision(decision_id: int) -> dict[str, Any]:
    entry = service.get_decision(decision_id)
    if entry is None:
        raise HTTPException(status_code=404, detail=f"风险决策 {decision_id} 不存在或已归档")
    return entry
