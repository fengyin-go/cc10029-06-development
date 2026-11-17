<template>
  <section class="page" data-module="antiblock">
    <header class="page-head">
      <div>
        <h2>反爬对抗管理</h2>
        <p class="page-desc">配置反爬对抗策略，在触发封禁前自动切换 UA/Referer/延迟。</p>
      </div>
      <div class="page-actions">
        <button class="btn primary" data-testid="open-create" type="button" @click="openCreate">登记反爬策略</button>
        <button class="btn" data-testid="export" type="button" @click="exportRows">导出反爬对抗清单</button>
      </div>
    </header>

    <div class="stat-row">
      <article v-for="item in stats" :key="item.label" class="stat-card">
        <span class="stat-label">{{ item.label }}</span>
        <strong class="stat-value">{{ item.value }}</strong>
      </article>
    </div>

    <form class="filter-bar" @submit.prevent="reload">
      <label v-for="field in filterFields" :key="field" class="filter-item">
        <span>{{ field }}</span>
        <input v-model="filters[field]" :data-testid="`filter-${field}`" :placeholder="`按${field}检索`" />
      </label>
      <button class="btn" data-testid="query" type="submit">查询</button>
      <button class="btn ghost" data-testid="reset" type="button" @click="resetFilters">重置条件</button>
    </form>

    <table class="data-table">
      <thead>
        <tr>
          <th v-for="column in columns" :key="column">{{ column }}</th>
          <th>可执行动作</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="row in rows" :key="String(row.id)" :data-testid="`row-${row.id}`" :data-status="String(row.status)">
          <td v-for="column in columns" :key="column">{{ row[column] ?? '—' }}</td>
          <td class="row-actions">
            <button
              v-for="action in actions"
              :key="action"
              class="link"
              type="button"
              :data-testid="`action-${row.id}-${action}`"
              @click="runAction(action, row)"
            >
              {{ action }}
            </button>
            <button class="link" type="button" :data-testid="`risk-${row.id}`" @click="openRisk(row)">
              风险决策
            </button>
          </td>
        </tr>
        <tr v-if="!rows.length">
          <td :colspan="columns.length + 1" class="empty-state">暂无反爬对抗数据，可先登记反爬策略</td>
        </tr>
      </tbody>
    </table>

    <section class="risk-panel" data-testid="risk-panel">
      <header class="risk-head">
        <div>
          <h3>反爬风险决策</h3>
          <p class="page-desc">
            风险评分、命中条件和代理切换建议由反爬对抗核定；判定标准：评分 {{ criteriaRange('风险评分') }}，
            熔断阈值 {{ criteriaRange('熔断阈值') }}，延迟范围 {{ criteriaRange('延迟范围') }} 秒。
          </p>
        </div>
        <div class="page-actions">
          <label class="filter-item">
            <span>当前代理</span>
            <input v-model="assessForm['当前代理']" data-testid="risk-current-proxy" placeholder="例如 PROX-0003" />
          </label>
          <button class="btn primary" type="button" data-testid="risk-assess" @click="submitAssess">提交风险评估</button>
          <button class="btn" type="button" data-testid="risk-refresh" @click="reloadDecisions">刷新决策</button>
        </div>
      </header>

      <form class="filter-bar" @submit.prevent="submitAssess">
        <label v-for="field in assessFields" :key="field" class="filter-item">
          <span>{{ field }}</span>
          <input v-model="assessForm[field]" :data-testid="`risk-input-${field}`" :placeholder="`请输入${field}`" />
        </label>
        <label class="filter-item">
          <span>触发封禁</span>
          <select v-model="assessForm['触发封禁']" data-testid="risk-input-触发封禁">
            <option value="否">否</option>
            <option value="是">是</option>
          </select>
        </label>
        <label class="filter-item">
          <span>触发验证码</span>
          <select v-model="assessForm['触发验证码']" data-testid="risk-input-触发验证码">
            <option value="否">否</option>
            <option value="是">是</option>
          </select>
        </label>
      </form>

      <p v-if="riskMessage" class="risk-note" data-testid="risk-message">{{ riskMessage }}</p>

      <table class="data-table risk-table">
        <thead>
          <tr>
            <th>决策编号</th>
            <th>请求标识</th>
            <th>策略版本</th>
            <th>风险评分</th>
            <th>命中条件</th>
            <th>决策策略</th>
            <th>目标区域</th>
            <th>熔断状态</th>
            <th>代理切换建议</th>
            <th>生效边界</th>
            <th>决策状态</th>
            <th>重复送交</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="item in decisions"
            :key="String(item.id)"
            :data-testid="`risk-row-${item.请求标识}`"
            :data-decision-status="String(item.决策状态)"
          >
            <td>{{ item.决策编号 }}</td>
            <td>{{ item.请求标识 }}</td>
            <td>{{ item.策略版本 }}</td>
            <td>
              <span class="risk-score">{{ item.风险评分 }}</span>
              <span class="risk-threshold">阈值 {{ item.熔断阈值 }}</span>
            </td>
            <td>{{ item.命中条件 }}</td>
            <td>{{ item.决策策略 }}</td>
            <td>{{ item.目标区域 }}</td>
            <td>{{ item.熔断状态 }}</td>
            <td>{{ item.代理切换建议 }}</td>
            <td>{{ item.生效边界 }}</td>
            <td>{{ item.决策状态 }}</td>
            <td>{{ item.重复送交次数 }}</td>
          </tr>
          <tr v-if="!decisions.length">
            <td :colspan="12" class="empty-state">暂无风险决策，填写请求结果后提交评估</td>
          </tr>
        </tbody>
      </table>

      <div v-if="selectedRisk" class="risk-detail" data-testid="risk-detail">
        <h4>{{ selectedRisk.策略名称 }}（{{ selectedRisk.策略版本 }}）</h4>
        <dl>
          <template v-for="item in riskDetailRows" :key="item.label">
            <dt>{{ item.label }}</dt>
            <dd>{{ item.value }}</dd>
          </template>
        </dl>
        <h4>重复请求核对</h4>
        <ul class="risk-check">
          <li v-for="item in selectedRisk.请求核对" :key="item.请求标识">
            请求 {{ item.请求标识 }}：决策 {{ item.决策数 }} 条，有效决策 {{ item.有效决策数 }} 条
          </li>
          <li v-if="!selectedRisk.请求核对.length">该策略还没有请求进入风险评估</li>
        </ul>
        <div class="page-actions">
          <label class="filter-item">
            <span>熔断阈值调整（生效中）</span>
            <input v-model="thresholdValue" data-testid="threshold-input" placeholder="例如 75" />
          </label>
          <button class="btn" type="button" data-testid="threshold-apply" @click="applyThreshold">调整阈值</button>
        </div>
        <p v-if="thresholdMessage" class="risk-note" data-testid="threshold-message">{{ thresholdMessage }}</p>
      </div>
    </section>

    <div v-if="showCreate" class="modal-backdrop" data-testid="create-modal">
      <form class="modal" @submit.prevent="submitCreate">
        <h3>登记反爬策略</h3>
        <label v-for="field in columns" :key="field" class="create-field">
          <span>{{ field }}</span>
          <input v-model="createValues[field]" :data-testid="`create-${field}`" required />
        </label>
        <div class="page-actions">
          <button class="btn" type="button" @click="showCreate = false">取消</button>
          <button class="btn primary" data-testid="submit-create" type="submit" :disabled="creating">
            {{ creating ? '提交中…' : '确认登记' }}
          </button>
        </div>
      </form>
    </div>

    <footer class="page-foot">
      <span>共 {{ total }} 条反爬对抗记录</span>
      <span v-if="errorMessage" class="error-text">{{ errorMessage }}</span>
    </footer>
  </section>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'

import { fetchJson, request } from '@/api/client'

type Row = Record<string, string | number | null>
type RiskDecision = Record<string, string | number | boolean | null>
type StrategyRisk = {
  策略编号: string
  策略名称: string
  策略版本: string
  触发条件: string
  延迟范围: string
  UA伪装: string
  熔断阈值: string
  风险评分: number
  命中条件: string
  代理切换建议: string
  决策数量: number
  有效决策数: number
  重复送交次数: number
  请求核对: { 请求标识: string; 决策数: number; 有效决策数: number }[]
  最近决策: RiskDecision | null
}
type Criteria = {
  判定标准: { 判定项: string; 下限: number; 上限: number; 说明: string }[]
  必需字段: string[]
  判定规则: string
}

const ENDPOINT = '/api/antiblock'
const RISK_ENDPOINT = '/api/risk'
const columns = ["策略编号", "策略名称", "触发条件", "延迟范围", "UA伪装", "Referer生成", "Cookie策略", "熔断阈值"]
const actions = ["提交校验", "启用配置", "停用配置"]
const statuses = ["草稿", "待校验", "已启用", "已停用"]
const metricNames = ["反爬策略总数", "待校验反爬策略", "已启用反爬策略"]
const assessFields = ["请求标识", "策略编号", "响应状态码", "响应耗时", "连续失败次数", "目标区域"]

const rows = ref<Row[]>([])
const total = ref(0)
const errorMessage = ref('')
const filters = ref<Record<string, string>>({})
const filterFields = columns.slice(0, 3)
const showCreate = ref(false)
const creating = ref(false)
const createValues = ref<Record<string, string>>({})
const stats = computed(() => [
  { label: metricNames[0], value: total.value },
  { label: metricNames[1], value: rows.value.filter((row) => row.status === statuses[1]).length },
  { label: metricNames[2], value: rows.value.filter((row) => row.status === statuses[statuses.length - 1]).length },
])

const criteria = ref<Criteria>({ 判定标准: [], 必需字段: [], 判定规则: '' })
const decisions = ref<RiskDecision[]>([])
const riskMessage = ref('')
const assessForm = reactive<Record<string, string>>({
  请求标识: `REQ-${Date.now()}`,
  策略编号: '',
  响应状态码: '403',
  响应耗时: '2600',
  连续失败次数: '2',
  目标区域: '',
  触发封禁: '否',
  触发验证码: '否',
  当前代理: '',
})
const selectedRisk = ref<StrategyRisk | null>(null)
const thresholdValue = ref('')
const thresholdMessage = ref('')

const riskDetailRows = computed(() => {
  const data = selectedRisk.value
  if (!data) return []
  return [
    { label: '策略编号', value: data.策略编号 },
    { label: '策略版本', value: data.策略版本 },
    { label: '触发条件', value: data.触发条件 },
    { label: '延迟范围（秒）', value: data.延迟范围 },
    { label: '熔断阈值', value: data.熔断阈值 },
    { label: '风险评分', value: String(data.风险评分) },
    { label: '命中条件', value: data.命中条件 },
    { label: '代理切换建议', value: data.代理切换建议 },
    { label: '决策数量', value: String(data.决策数量) },
    { label: '有效决策数', value: String(data.有效决策数) },
    { label: '重复送交次数', value: String(data.重复送交次数) },
  ]
})

function criteriaRange(name: string): string {
  const item = criteria.value.判定标准.find((entry) => entry.判定项 === name)
  return item ? `${item.下限}-${item.上限}` : '—'
}

function resetFilters() {
  filters.value = {}
  void reload()
}

async function exportRows() {
  errorMessage.value = ''
  const query = new URLSearchParams(filters.value).toString()
  try {
    const response = await request(`${ENDPOINT}/export?${query}`)
    if (!response.ok) throw new Error('导出失败，请稍后重试')
    const url = URL.createObjectURL(await response.blob())
    const link = document.createElement('a')
    link.href = url
    link.download = 'antiblock.csv'
    link.click()
    URL.revokeObjectURL(url)
  } catch (error) {
    errorMessage.value = error instanceof Error ? error.message : '导出失败'
  }
}

function openCreate() {
  createValues.value = Object.fromEntries(columns.map((field) => [field, '']))
  errorMessage.value = ''
  showCreate.value = true
}

async function submitCreate() {
  creating.value = true
  errorMessage.value = ''
  try {
    const response = await request(ENDPOINT, {
      method: 'POST', body: JSON.stringify(createValues.value),
    })
    const payload = await response.json()
    if (!response.ok || !payload.ok) throw new Error(payload.message || '登记失败')
    showCreate.value = false
    await reload()
  } catch (error) {
    errorMessage.value = error instanceof Error ? error.message : '登记失败'
  } finally {
    creating.value = false
  }
}

async function runAction(action: string, row: Row) {
  errorMessage.value = ''
  try {
    const response = await request(`${ENDPOINT}/${row.id}/actions`, {
      method: 'POST',
      body: JSON.stringify({ action }),
    })
    if (!response.ok) {
      throw new Error('反爬对抗动作未生效，请稍后重试')
    }
    await reload()
    if (selectedRisk.value?.策略编号 === row['策略编号']) await openRisk(row)
    await reloadDecisions()
  } catch (error) {
    errorMessage.value = error instanceof Error ? error.message : '反爬对抗操作失败'
  }
}

async function openRisk(row: Row) {
  errorMessage.value = ''
  thresholdMessage.value = ''
  try {
    const detail = await fetchJson<Record<string, unknown>>(`${ENDPOINT}/${row.id}`)
    selectedRisk.value = (detail.风险决策 as StrategyRisk) ?? null
    if (selectedRisk.value) {
      assessForm.策略编号 = selectedRisk.value.策略编号
      assessForm.目标区域 = assessForm.目标区域 || regionFromCondition(selectedRisk.value.触发条件)
      thresholdValue.value = String(selectedRisk.value.熔断阈值 ?? '')
    }
  } catch (error) {
    errorMessage.value = error instanceof Error ? error.message : '风险评分读取失败'
  }
}

function regionFromCondition(condition: string): string {
  const match = /区域\s*[=:：]\s*([^\s,，;；]+)/.exec(condition || '')
  return match ? match[1] : ''
}

async function submitAssess() {
  riskMessage.value = ''
  errorMessage.value = ''
  const payload: Record<string, unknown> = {}
  for (const field of [...assessFields, '触发封禁', '触发验证码', '当前代理']) {
    if (assessForm[field] !== '') payload[field] = assessForm[field]
  }
  try {
    const response = await request(`${RISK_ENDPOINT}/assess`, {
      method: 'POST', body: JSON.stringify(payload),
    })
    const result = await response.json()
    riskMessage.value = result.message ?? ''
    if (result.entry) assessForm.策略编号 = String(result.entry.策略编号 ?? assessForm.策略编号)
    await reloadDecisions()
  } catch (error) {
    riskMessage.value = error instanceof Error ? error.message : '风险评估失败'
  }
}

async function reloadDecisions() {
  try {
    const payload = await fetchJson<{ items: RiskDecision[] }>(`${RISK_ENDPOINT}?size=50`)
    decisions.value = payload.items ?? []
    const strategyCode = assessForm.策略编号
    if (strategyCode) {
      const match = rows.value.find((row) => String(row.策略编号) === strategyCode)
      if (match) {
        const detail = await fetchJson<Record<string, unknown>>(`${ENDPOINT}/${match.id}`)
        selectedRisk.value = (detail.风险决策 as StrategyRisk) ?? selectedRisk.value
      }
    }
  } catch {
    riskMessage.value = '风险决策数据集读取失败'
  }
}

async function applyThreshold() {
  thresholdMessage.value = ''
  const match = rows.value.find((row) => String(row.策略编号) === selectedRisk.value?.策略编号)
  if (!match) {
    thresholdMessage.value = '请先从策略列表选择一条策略'
    return
  }
  try {
    const response = await request(`${ENDPOINT}/${match.id}/threshold`, {
      method: 'POST', body: JSON.stringify({ 熔断阈值: thresholdValue.value }),
    })
    const result = await response.json()
    thresholdMessage.value = result.message ?? ''
    if (result.ok) {
      await reload()
      await openRisk(match)
      await reloadDecisions()
    }
  } catch (error) {
    thresholdMessage.value = error instanceof Error ? error.message : '阈值调整失败'
  }
}

async function reload() {
  errorMessage.value = ''
  const query = new URLSearchParams(filters.value as Record<string, string>).toString()
  try {
    const response = await request(`${ENDPOINT}?${query}`)
    if (!response.ok) {
      throw new Error('反爬策略列表读取失败')
    }
    const payload = await response.json()
    rows.value = payload.items ?? []
    total.value = payload.total ?? rows.value.length
  } catch (error) {
    errorMessage.value = error instanceof Error ? error.message : '反爬对抗列表读取失败'
  }
}

onMounted(async () => {
  try {
    criteria.value = await fetchJson<Criteria>(`${RISK_ENDPOINT}/criteria`)
  } catch {
    criteria.value = { 判定标准: [], 必需字段: [], 判定规则: '' }
  }
  await reload()
  await reloadDecisions()
})
</script>

<style scoped>
.risk-panel { margin-top: 18px; padding: 14px; background: #fff; border: 1px solid var(--border); border-radius: 8px; }
.risk-head { display: flex; justify-content: space-between; gap: 12px; align-items: flex-start; }
.risk-head h3 { margin: 0; font-size: 15px; }
.risk-note { font-size: 12px; color: #b45309; background: #fffbeb; border: 1px solid #fde68a; border-radius: 6px; padding: 6px 10px; }
.risk-table { margin-top: 8px; }
.risk-score { font-weight: 600; color: #b42318; }
.risk-threshold { color: var(--muted); font-size: 11px; margin-left: 4px; }
.risk-detail { margin-top: 14px; padding: 12px; border: 1px dashed var(--border); border-radius: 8px; }
.risk-detail h4 { margin: 0 0 8px; font-size: 13px; }
.risk-detail dl { display: grid; grid-template-columns: 120px 1fr; gap: 4px 8px; margin: 0 0 10px; }
.risk-detail dt { color: var(--muted); font-size: 12px; }
.risk-detail dd { margin: 0; font-size: 13px; }
.risk-check { margin: 0 0 10px; padding-left: 18px; font-size: 12px; color: #334155; }
</style>
