<script setup lang="ts">
import { computed, onMounted, watch } from 'vue'
import { useRoute } from 'vue-router'
import MainLayout from '@/layouts/MainLayout.vue'
import { useGlobalFilterStore } from '@/stores/globalFilter'
import { useAuthStore } from '@/stores/auth'
import { validateMapping } from '@/api/logs'
import { ES_FIELD_MAPPING } from '@/constants/esFieldMapping'

const route = useRoute()
const globalStore = useGlobalFilterStore()
const authStore = useAuthStore()

// 非登录页且已认证时才渲染 MainLayout，避免未登录刷新闪现布局
const showLayout = computed(() => {
  return !route.meta.guest && authStore.isAuthenticated
})

async function runMappingValidation() {
  try {
    const result = await validateMapping()
    globalStore.setMappingValidation(result.valid, result.missing_fields)
    if (!result.valid) {
      console.warn('[SenseMind] 字段映射校验：缺失字段', result.missing_fields)
    }
  } catch {
    globalStore.setMappingValidation(true, [])
  }
  console.info('[SenseMind] 已加载字段映射', ES_FIELD_MAPPING.length, '个字段')
}

onMounted(() => {
  if (authStore.isAuthenticated) {
    runMappingValidation()
  }
})

watch(() => authStore.isAuthenticated, (val) => {
  if (val) runMappingValidation()
})
</script>

<template>
  <MainLayout v-if="showLayout" />
  <router-view v-else />
</template>
