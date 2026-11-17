<template>
  <section class="page" data-module="proxy">
    <header class="page-head">
      <div>
        <h2>代理池管理</h2>
        <p class="page-desc">管理代理 IP 的来源、存活检测和区域分发，为采集请求提供透明的代理切换。</p>
      </div>
      <div class="page-actions">
        <button class="btn primary" data-testid="open-create" type="button" @click="openCreate">登记代理节点</button>
        <button class="btn" data-testid="export" type="button" @click="exportRows">导出代理池清单</button>
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
          </td>
        </tr>
        <tr v-if="!rows.length">
          <td :colspan="columns.length + 1" class="empty-state">暂无代理池数据，可先登记代理节点</td>
        </tr>
      </tbody>
    </table>

    <section class="switch-panel" data-testid="switch-panel">
      <header class="switch-head">
        <div>
          <h3>代理切换清单</h3>
          <p class="page-desc">
            由反爬风险决策数据集生成，只取有效决策；切换区域服从决策的目标区域，熔断决策才允许换出口。
          </p>
        </div>
        <div class="page-actions">
          <button class="btn primary" type="button" data-testid="switch-build" @click="buildSwitches">生成切换清单</button>
        </div>
      </header>
      <p v-if="switchMessage" class="switch-note" data-testid="switch-message">{{ switchMessage }}</p>
      <table class="data-table">
        <thead>
          <tr>
            <th>清单编号</th>
            <th>决策编号</th>
            <th>请求标识</th>
            <th>策略版本</th>
            <th>目标区域</th>
            <th>熔断状态</th>
            <th>切换类型</th>
            <th>当前代理</th>
            <th>切换代理</th>
            <th>决策生效边界</th>
            <th>切换状态</th>
            <th>操作</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="item in switches"
            :key="String(item.id)"
            :data-testid="`switch-row-${item.清单编号}`"
            :data-switch-status="String(item.切换状态)"
          >
            <td>{{ item.清单编号 }}</td>
            <td>{{ item.决策编号 }}</td>
            <td>{{ item.请求标识 }}</td>
            <td>{{ item.策略版本 }}</td>
            <td>{{ item.目标区域 }}</td>
            <td>{{ item.熔断状态 }}</td>
            <td>{{ item.切换类型 }}</td>
            <td>{{ item.当前代理 || '—' }}</td>
            <td>{{ item.切换代理 || '—' }}</td>
            <td>{{ item.决策生效边界 }}</td>
            <td>{{ item.切换状态 }}</td>
            <td class="row-actions">
              <button
                class="link"
                type="button"
                :data-testid="`switch-apply-${item.清单编号}`"
                :disabled="item.切换状态 !== '待切换'"
                @click="applySwitch(item)"
              >
                执行切换
              </button>
            </td>
          </tr>
          <tr v-if="!switches.length">
            <td :colspan="12" class="empty-state">暂无代理切换清单，先在反爬对抗提交风险评估后生成</td>
          </tr>
        </tbody>
      </table>
    </section>

    <div v-if="showCreate" class="modal-backdrop" data-testid="create-modal">
      <form class="modal" @submit.prevent="submitCreate">
        <h3>登记代理节点</h3>
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
      <span>共 {{ total }} 条代理池记录</span>
      <span v-if="errorMessage" class="error-text">{{ errorMessage }}</span>
    </footer>
  </section>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'

import { fetchJson, request } from '@/api/client'

type Row = Record<string, string | number | null>

const ENDPOINT = '/api/proxy'
const columns = ["节点编号", "IP地址", "端口号", "协议类型", "匿程度", "响应延迟", "存活检测", "所属区域"]
const actions = ["提交校验", "启用配置", "停用配置"]
const statuses = ["草稿", "待校验", "已启用", "已停用"]
const metricNames = ["代理节点总数", "待校验代理节点", "已启用代理节点"]

type SwitchItem = Record<string, string | number | boolean | null>

const rows = ref<Row[]>([])
const switches = ref<SwitchItem[]>([])
const switchMessage = ref('')
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
    link.download = 'proxy.csv'
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
      throw new Error('代理池动作未生效，请稍后重试')
    }
    await reload()
  } catch (error) {
    errorMessage.value = error instanceof Error ? error.message : '代理池操作失败'
  }
}

async function reload() {
  errorMessage.value = ''
  const query = new URLSearchParams(filters.value as Record<string, string>).toString()
  try {
    const response = await request(`${ENDPOINT}?${query}`)
    if (!response.ok) {
      throw new Error('代理节点列表读取失败')
    }
    const payload = await response.json()
    rows.value = payload.items ?? []
    total.value = payload.total ?? rows.value.length
  } catch (error) {
    errorMessage.value = error instanceof Error ? error.message : '代理池列表读取失败'
  }
}

async function reloadSwitches() {
  try {
    const payload = await fetchJson<{ items: SwitchItem[] }>(`${ENDPOINT}/switches`)
    switches.value = payload.items ?? []
  } catch {
    switchMessage.value = '代理切换清单读取失败'
  }
}

async function buildSwitches() {
  switchMessage.value = ''
  try {
    const response = await request(`${ENDPOINT}/switches/rebuild`, {
      method: 'POST', body: JSON.stringify({}),
    })
    const result = await response.json()
    switchMessage.value = result.message ?? ''
    await reloadSwitches()
  } catch (error) {
    switchMessage.value = error instanceof Error ? error.message : '代理切换清单生成失败'
  }
}

async function applySwitch(item: SwitchItem) {
  switchMessage.value = ''
  try {
    const response = await request(`${ENDPOINT}/switches/${item.id}/apply`, { method: 'POST' })
    const result = await response.json()
    switchMessage.value = result.message ?? ''
    await reloadSwitches()
  } catch (error) {
    switchMessage.value = error instanceof Error ? error.message : '代理切换执行失败'
  }
}

onMounted(() => {
  void reload()
  void reloadSwitches()
})
</script>

<style scoped>
.switch-panel { margin-top: 18px; padding: 14px; background: #fff; border: 1px solid var(--border); border-radius: 8px; }
.switch-head { display: flex; justify-content: space-between; gap: 12px; align-items: flex-start; }
.switch-head h3 { margin: 0; font-size: 15px; }
.switch-note { font-size: 12px; color: #0f5132; background: #ecfdf3; border: 1px solid #a7f3d0; border-radius: 6px; padding: 6px 10px; }
</style>
