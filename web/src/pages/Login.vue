<script setup lang="ts">
import { ref, computed } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { User, Lock, Key, ArrowRight, ArrowLeft } from '@element-plus/icons-vue'
import { checkUser, login, type CheckUserResult } from '@/api/auth'
import { useAuthStore } from '@/stores/auth'

const router = useRouter()
const authStore = useAuthStore()

const step = ref<1 | 2 | 3>(1)
const loading = ref(false)
const errorMsg = ref('')

const form = ref({
  username: '',
  password: '',
  totpCode: '',
})

const checkResult = ref<CheckUserResult | null>(null)

const needPassword = computed(() => {
  const mode = checkResult.value?.auth_mode
  return mode === 'PASSWORD_ONLY' || mode === 'PASSWORD_AND_TOTP'
})

const needTotp = computed(() => {
  const mode = checkResult.value?.auth_mode
  return mode === 'TOTP_ONLY' || mode === 'PASSWORD_AND_TOTP'
})

const stepTitle = computed(() => {
  if (step.value === 1) return '账户登录'
  if (step.value === 2) {
    if (needPassword.value && needTotp.value) return '请输入密码'
    if (needTotp.value) return '请输入验证码'
    return '请输入密码'
  }
  return '请输入验证码'
})

const canSubmit = computed(() => {
  if (step.value === 1) return !!form.value.username.trim()
  if (step.value === 2) {
    if (needPassword.value && needTotp.value) return !!form.value.password
    if (needPassword.value) return !!form.value.password
    if (needTotp.value) return form.value.totpCode.length === 6
  }
  if (step.value === 3) return form.value.totpCode.length === 6
  return false
})

function resetSteps() {
  step.value = 1
  checkResult.value = null
  form.value.password = ''
  form.value.totpCode = ''
  errorMsg.value = ''
}

async function handleCheckUser() {
  errorMsg.value = ''
  if (!form.value.username.trim()) return
  loading.value = true
  try {
    const result = await checkUser(form.value.username.trim())
    if (!result.exists) {
      errorMsg.value = '用户名或口令错误'
      return
    }
    checkResult.value = result
    step.value = 2
  } catch (e: any) {
    errorMsg.value = e?.response?.data?.detail || '请求失败，请稍后重试'
  } finally {
    loading.value = false
  }
}

async function handleNext() {
  errorMsg.value = ''
  // PASSWORD_AND_TOTP: 密码验证通过后进入 Step 3 输 TOTP
  if (needPassword.value && needTotp.value && step.value === 2) {
    step.value = 3
    return
  }
  await handleLogin()
}

async function handleLogin() {
  errorMsg.value = ''
  loading.value = true
  try {
    const result = await login({
      username: form.value.username.trim(),
      password: form.value.password || undefined,
      totp_code: form.value.totpCode || undefined,
    })
    authStore.setAuth(result.access_token, result.user as any)
    ElMessage.success('登录成功')
    router.push('/monitor/dashboard')
  } catch (e: any) {
    const status = e?.response?.status
    const detail = e?.response?.data?.detail
    if (status === 403) {
      errorMsg.value = detail || '账号已被禁用，请联系管理员'
    } else if (status === 429) {
      errorMsg.value = detail || '请求过于频繁，请稍后再试'
    } else if (status === 400 && e?.response?.data?.detail?.includes('TOTP')) {
      errorMsg.value = detail
    } else {
      errorMsg.value = detail || '用户名或口令错误'
    }
  } finally {
    loading.value = false
  }
}

function goBack() {
  resetSteps()
}
</script>

<template>
  <div class="login-container">
    <div class="login-card">
      <div class="login-header">
        <img src="/logo.svg" alt="SenseMind" class="logo-img" />
        <span class="logo-text">SenseMind</span>
      </div>

      <div class="login-body">
        <h2 class="login-title">
          <span class="title-bar"></span>
          {{ stepTitle }}
        </h2>

        <!-- Step 1: 用户名 -->
        <div v-if="step === 1" class="step-content">
          <el-input
            v-model="form.username"
            placeholder="请输入用户名"
            size="large"
            @keyup.enter="handleCheckUser"
          >
            <template #prefix>
              <el-icon><User /></el-icon>
            </template>
          </el-input>
          <el-button
            type="primary"
            size="large"
            class="submit-btn"
            :loading="loading"
            :disabled="!canSubmit"
            @click="handleCheckUser"
          >
            下一步
            <el-icon class="el-icon--right"><ArrowRight /></el-icon>
          </el-button>
        </div>

        <!-- Step 2: 密码 / TOTP -->
        <div v-else-if="step === 2" class="step-content">
          <div class="user-info">
            <el-icon><User /></el-icon>
            <span>{{ form.username }}</span>
            <el-button text size="small" class="switch-user-btn" @click="goBack">
              <el-icon><ArrowLeft /></el-icon>
              切换用户
            </el-button>
          </div>

          <el-input
            v-if="needPassword"
            v-model="form.password"
            type="password"
            placeholder="请输入密码"
            size="large"
            show-password
            @keyup.enter="handleNext"
          >
            <template #prefix>
              <el-icon><Lock /></el-icon>
            </template>
          </el-input>

          <el-input
            v-if="needTotp && !needPassword"
            v-model="form.totpCode"
            placeholder="请输入6位验证码"
            size="large"
            maxlength="6"
            @keyup.enter="handleLogin"
          >
            <template #prefix>
              <el-icon><Key /></el-icon>
            </template>
          </el-input>

          <el-button
            type="primary"
            size="large"
            class="submit-btn"
            :loading="loading"
            :disabled="!canSubmit"
            @click="handleNext"
          >
            {{ needPassword && needTotp ? '下一步' : '登录' }}
          </el-button>
        </div>

        <!-- Step 3: TOTP（仅 PASSWORD_AND_TOTP） -->
        <div v-else-if="step === 3" class="step-content">
          <div class="user-info">
            <el-icon><User /></el-icon>
            <span>{{ form.username }}</span>
            <el-button text size="small" class="switch-user-btn" @click="goBack">
              <el-icon><ArrowLeft /></el-icon>
              重新开始
            </el-button>
          </div>

          <el-input
            v-model="form.totpCode"
            placeholder="请输入6位验证码"
            size="large"
            maxlength="6"
            @keyup.enter="handleLogin"
          >
            <template #prefix>
              <el-icon><Key /></el-icon>
            </template>
          </el-input>

          <el-button
            type="primary"
            size="large"
            class="submit-btn"
            :loading="loading"
            :disabled="!canSubmit"
            @click="handleLogin"
          >
            登录
          </el-button>
        </div>

        <transition name="fade">
          <div v-if="errorMsg" class="error-msg">{{ errorMsg }}</div>
        </transition>
      </div>

      <div class="login-footer">SenseMind SOC 智能分析平台</div>
    </div>
  </div>
</template>

<style scoped lang="scss">
.login-container {
  position: fixed;
  inset: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  background: $color-nav-bg;
  background-image:
    linear-gradient(rgba(255, 255, 255, 0.03) 1px, transparent 1px),
    linear-gradient(90deg, rgba(255, 255, 255, 0.03) 1px, transparent 1px);
  background-size: 32px 32px;
}

.login-card {
  width: 420px;
  background: $color-bg-elevated;
  border-radius: $radius-lg;
  box-shadow: 0 20px 60px -10px rgba(0, 0, 0, 0.5);
  overflow: hidden;
}

.login-header {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 10px;
  padding: 32px 32px 16px;

  .logo-img {
    height: 32px;
    width: auto;
  }
  .logo-text {
    font-family: $font-mono;
    font-size: 20px;
    font-weight: 700;
    color: $color-nav-bg;
    letter-spacing: 0.5px;
  }
}

.login-body {
  padding: 8px 32px 24px;
}

.login-title {
  display: flex;
  align-items: center;
  gap: 10px;
  font-size: 16px;
  font-weight: 600;
  color: $color-text-primary;
  margin-bottom: 24px;

  .title-bar {
    width: 3px;
    height: 16px;
    background: $color-primary;
    border-radius: 2px;
  }
}

.step-content {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.user-info {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px 14px;
  background: $color-bg-soft;
  border-radius: $radius-md;
  font-size: 13px;
  color: $color-text-regular;

  .switch-user-btn {
    margin-left: auto;
    color: $color-primary;
  }
}

.submit-btn {
  width: 100%;
  margin-top: 4px;
}

.error-msg {
  margin-top: 12px;
  padding: 8px 12px;
  background: rgba(239, 68, 68, 0.08);
  border-radius: $radius-md;
  color: $color-danger;
  font-size: 13px;
  text-align: center;
}

.login-footer {
  padding: 16px 32px 24px;
  text-align: center;
  font-size: 12px;
  color: $color-text-placeholder;
}

.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.2s ease;
}
.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}
</style>
