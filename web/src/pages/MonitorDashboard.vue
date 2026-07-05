<script setup lang="ts">
import { computed } from 'vue'
import MetricCard from '@/components/monitor/MetricCard.vue'
import AiOverviewCard from '@/components/monitor/AiOverviewCard.vue'
import SocAttackChart from '@/components/monitor/SocAttackChart.vue'
import ThreatVerdictChart from '@/components/monitor/ThreatVerdictChart.vue'
import ThreatSourceChart from '@/components/monitor/ThreatSourceChart.vue'
import SystemInfoChart from '@/components/monitor/SystemInfoChart.vue'
import SkeletonCard from '@/components/common/SkeletonCard.vue'
import { useAiMetrics } from '@/composables/useAiMetrics'
import { useAutoRefresh } from '@/composables/useAutoRefresh'
import { useAnalysisRouter } from '@/composables/useAnalysisRouter'
import { storeToRefs } from 'pinia'
import { useGlobalFilterStore } from '@/stores/globalFilter'
import { RISK_LABEL_MAP, RISK_COLOR_MAP } from '@/constants/esFieldMapping'

const { data, loading, fetch } = useAiMetrics()
const { goFromMetricCard } = useAnalysisRouter()
const { timeRange } = storeToRefs(useGlobalFilterStore())

// 系统资源监控（SystemInfoChart）自带 5s 刷新，此处仅刷新核心指标数据
useAutoRefresh(fetch)

const confidenceTip = computed(() => {
  if (!data.value) return ''
  return `平均可信度 ${data.value.ai_avg_confidence}，分布范围 0.0-1.0`
})

const riskLabel = computed(() =>
  data.value ? RISK_LABEL_MAP[data.value.risk_level] : '',
)

const riskColor = computed(() =>
  data.value ? RISK_COLOR_MAP[data.value.risk_level] : '#94a3b8',
)
</script>

<template>
  <div class="monitor-dashboard">
    <!-- 1. 顶部核心指标卡片区（含平均可信度） -->
    <section class="section metrics-section">
      <div class="section-title">核心指标</div>
      <div class="metrics-grid">
        <template v-if="loading && !data">
          <SkeletonCard v-for="i in 5" :key="i" height="96px" />
        </template>
        <template v-else>
          <MetricCard
            title="风险等级"
            :value="0"
            :risk-level="data?.risk_level"
            :loading="loading"
            @click="goFromMetricCard('risk', timeRange)"
          >
            <template #default>
              <div class="risk-badge-large" :style="{ background: riskColor }">
                {{ riskLabel || '-' }}
              </div>
            </template>
          </MetricCard>
          <MetricCard
            title="总告警数"
            :value="data?.total_alerts || 0"
            :loading="loading"
            @click="goFromMetricCard('total_alerts', timeRange)"
          />
          <MetricCard
            title="受害资产数"
            :value="data?.victim_assets || 0"
            unit="台"
            :loading="loading"
            @click="goFromMetricCard('victim_assets', timeRange)"
          />
          <MetricCard
            title="攻击者数量"
            :value="data?.attacker_count || 0"
            unit="个"
            :loading="loading"
            @click="goFromMetricCard('attacker_count', timeRange)"
          />
          <AiOverviewCard
            title="平均可信度"
            :value="data?.ai_avg_confidence || 0"
            :decimals="2"
            :prev="data?.ai_confidence_prev"
            :hover-tip="confidenceTip"
            :loading="loading"
            compact
          />
        </template>
      </div>
    </section>

    <!-- 2. 攻击归因与威胁分析区 -->
    <section class="section charts-section">
      <div class="section-title">攻击归因与威胁分析</div>
      <div class="charts-grid">
        <SocAttackChart
          :data="data?.soc_attack_distribution || []"
          :loading="loading"
        />
        <ThreatVerdictChart
          :data="data?.threat_verdict_distribution || { reliable: 0, suspicious: 0, unreliable: 0, total: 0 }"
          :loading="loading"
        />
        <ThreatSourceChart
          :data="data?.threat_source_distribution || { system_alert: 0, semantic_analysis: 0, total: 0 }"
          :loading="loading"
        />
      </div>
    </section>

    <!-- 3. 系统资源监控区 -->
    <section class="section system-section">
      <div class="section-title">系统资源监控</div>
      <div class="system-grid">
        <SystemInfoChart />
      </div>
    </section>
  </div>
</template>

<style scoped lang="scss">
.monitor-dashboard {
  display: flex;
  flex-direction: column;
  gap: 24px;
}

.section {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.section-title {
  font-size: 14px;
  font-weight: 700;
  color: $color-text-regular;
  padding-left: 8px;
  border-left: 3px solid $color-primary;
}

.metrics-grid {
  display: grid;
  grid-template-columns: repeat(5, 1fr);
  gap: 16px;
}

.charts-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 16px;
}

.system-grid {
  display: grid;
  grid-template-columns: 1fr;
  gap: 16px;
}

.risk-badge-large {
  display: inline-block;
  padding: 6px 20px;
  border-radius: 6px;
  font-size: 22px;
  font-weight: 700;
  color: #fff;
  line-height: 1.2;
}

// 响应式
@media (max-width: 1440px) {
  .metrics-grid {
    grid-template-columns: repeat(3, 1fr);
  }
  .charts-grid {
    grid-template-columns: 1fr 1fr;
  }
}

@media (max-width: 1024px) {
  .metrics-grid,
  .charts-grid {
    grid-template-columns: 1fr 1fr;
  }
}

@media (max-width: 768px) {
  .metrics-grid,
  .charts-grid {
    grid-template-columns: 1fr;
  }
}
</style>
