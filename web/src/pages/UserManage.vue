<script setup lang="ts">
import { ref, computed, onMounted, nextTick } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Plus, Refresh, Delete, Edit } from '@element-plus/icons-vue'
import QRCode from 'qrcode'
import {
  listUsers, createUser, updateUser, deleteUser, resetPassword,
  enableTotp, disableTotp, getTotpSecret, type UserItem, type AuthMode,
} from '@/api/user'
import { useAuthStore } from '@/stores/auth'

const authStore = useAuthStore()

const users = ref<UserItem[]>([])
const loading = ref(false)
const keyword = ref('')

const filteredUsers = computed(() => {
  if (!keyword.value.trim()) return users.value
  const kw = keyword.value.trim().toLowerCase()
  return users.value.filter((u) => u.username.toLowerCase().includes(kw))
})

async function fetchUsers() {
  loading.value = true
  try {
    users.value = await listUsers()
  } catch (e: any) {
    ElMessage.error(e?.message || '加载用户列表失败')
    users.value = []
  } finally {
    loading.value = false
  }
}

onMounted(fetchUsers)

const AUTH_MODE_LABELS: Record<AuthMode, string> = {
  PASSWORD_ONLY: '仅密码',
  TOTP_ONLY: '仅 TOTP',
  PASSWORD_AND_TOTP: '密码 + TOTP',
}

function formatTime(t: string | null): string {
  if (!t) return '-'
  try {
    return new Date(t).toLocaleString('zh-CN', { hour12: false })
  } catch {
    return t
  }
}

// ---- 新建用户 ----
const createDialogVisible = ref(false)
const createForm = ref({
  username: '',
  password: '',
  role: 'user' as 'admin' | 'user',
  auth_mode: 'PASSWORD_ONLY' as AuthMode,
})

function openCreateDialog() {
  createForm.value = { username: '', password: '', role: 'user', auth_mode: 'PASSWORD_ONLY' }
  createDialogVisible.value = true
}

async function handleCreate() {
  if (!createForm.value.username.trim()) {
    ElMessage.warning('请输入用户名')
    return
  }
  if (createForm.value.auth_mode !== 'TOTP_ONLY' && createForm.value.password.length < 8) {
    ElMessage.warning('密码至少 8 位')
    return
  }
  try {
    const newUser = await createUser({
      username: createForm.value.username.trim(),
      password: createForm.value.auth_mode === 'TOTP_ONLY' ? undefined : createForm.value.password,
      role: createForm.value.role,
      auth_mode: createForm.value.auth_mode,
    })
    createDialogVisible.value = false
    fetchUsers()

    // 如果创建的是 TOTP 用户，弹出绑定信息（含二维码）
    if (createForm.value.auth_mode !== 'PASSWORD_ONLY' && newUser.id) {
      try {
        const result = await getTotpSecret(newUser.id)
        await showTotpBinding(result, `用户 ${newUser.username} 已创建，请绑定 TOTP`)
      } catch {
        ElMessage.warning('用户已创建，但获取 TOTP 密钥失败，请稍后在列表中查看')
      }
    } else {
      ElMessage.success('用户已创建')
    }
  } catch (e: any) {
    ElMessage.error(e?.response?.data?.detail || e?.message || '创建失败')
  }
}

// ---- 编辑用户（含密码重置 + TOTP 管理）----
const editDialogVisible = ref(false)
const editUser = ref<UserItem | null>(null)
const editForm = ref<{
  id: number
  role: 'admin' | 'user'
  auth_mode: AuthMode
  is_active: boolean
  totp_enabled: boolean
  new_password: string
} | null>(null)

function openEditDialog(user: UserItem) {
  editUser.value = user
  editForm.value = {
    id: user.id,
    role: user.role,
    auth_mode: user.auth_mode,
    is_active: user.is_active,
    totp_enabled: user.totp_enabled,
    new_password: '',
  }
  editDialogVisible.value = true
}

async function handleEdit() {
  if (!editForm.value) return
  // 新密码校验
  if (editForm.value.new_password && editForm.value.new_password.length < 8) {
    ElMessage.warning('新密码至少 8 位')
    return
  }
  try {
    await updateUser(editForm.value.id, {
      role: editForm.value.role,
      auth_mode: editForm.value.auth_mode,
      is_active: editForm.value.is_active,
    })
    if (editForm.value.new_password) {
      await resetPassword(editForm.value.id, { new_password: editForm.value.new_password })
    }
    ElMessage.success('用户已更新')
    editDialogVisible.value = false
    fetchUsers()
  } catch (e: any) {
    ElMessage.error(e?.response?.data?.detail || e?.message || '更新失败')
  }
}

// ---- 删除用户 ----
async function handleDelete(user: UserItem) {
  if (user.id === authStore.user?.id) {
    ElMessage.warning('不能删除当前登录用户')
    return
  }
  try {
    await ElMessageBox.confirm(`确认删除用户 "${user.username}" 吗？此操作不可恢复。`, '危险操作', {
      type: 'error', confirmButtonText: '删除', confirmButtonClass: 'el-button--danger',
    })
    await deleteUser(user.id)
    ElMessage.success('用户已删除')
    fetchUsers()
  } catch (e: any) {
    if (e === 'cancel') return
    ElMessage.error(e?.response?.data?.detail || e?.message || '删除失败')
  }
}

// ---- TOTP 绑定信息对话框（含二维码）----
const totpDialogVisible = ref(false)
const totpResult = ref<{ secret: string; uri: string } | null>(null)
const totpDialogTitle = ref('TOTP 绑定信息')
const qrDataUrl = ref('')

async function generateQrCode(uri: string) {
  try {
    qrDataUrl.value = await QRCode.toDataURL(uri, { width: 220, margin: 2 })
  } catch {
    qrDataUrl.value = ''
  }
}

async function showTotpBinding(result: { secret: string; uri: string }, title = 'TOTP 绑定信息') {
  totpResult.value = result
  totpDialogTitle.value = title
  totpDialogVisible.value = true
  await generateQrCode(result.uri)
}

// ---- 启用 TOTP ----
async function handleEnableTotp(user: UserItem) {
  try {
    const result = await enableTotp(user.id)
    await showTotpBinding(result, `TOTP 已启用 - ${user.username}`)
    if (editForm.value) editForm.value.totp_enabled = true
    fetchUsers()
  } catch (e: any) {
    ElMessage.error(e?.response?.data?.detail || e?.message || '启用 TOTP 失败')
  }
}

// ---- 查看 TOTP（管理员查看已有密钥）----
async function handleViewTotp(user: UserItem) {
  try {
    const result = await getTotpSecret(user.id)
    await showTotpBinding(result, `TOTP 密钥 - ${user.username}`)
  } catch (e: any) {
    ElMessage.error(e?.response?.data?.detail || e?.message || '获取 TOTP 密钥失败')
  }
}

// ---- TOTP 禁用（管理员直接禁用，无需验证码）----
async function handleDisableTotp(user: UserItem) {
  try {
    await ElMessageBox.confirm(`确认禁用用户 "${user.username}" 的 TOTP 吗？`, '提示', { type: 'warning' })
    await disableTotp(user.id, {})
    ElMessage.success('TOTP 已禁用')
    if (editForm.value) editForm.value.totp_enabled = false
    fetchUsers()
  } catch (e: any) {
    if (e === 'cancel') return
    ElMessage.error(e?.response?.data?.detail || e?.message || '禁用失败')
  }
}

function copyToClipboard(text: string) {
  navigator.clipboard.writeText(text).then(() => ElMessage.success('已复制'))
}
</script>

<template>
  <div class="user-manage">
    <div class="toolbar">
      <div class="toolbar-left">
        <el-input
          v-model="keyword"
          placeholder="按用户名搜索"
          clearable
          class="search-input"
        />
        <el-button :icon="Refresh" @click="fetchUsers">刷新</el-button>
      </div>
      <el-button type="primary" :icon="Plus" @click="openCreateDialog">新建用户</el-button>
    </div>

    <el-table v-loading="loading" :data="filteredUsers" stripe class="user-table">
      <el-table-column prop="username" label="用户名" min-width="120" />
      <el-table-column label="角色" min-width="90">
        <template #default="{ row }">
          <el-tag :type="row.role === 'admin' ? 'danger' : 'info'" size="small">
            {{ row.role === 'admin' ? '管理员' : '普通用户' }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column label="认证模式" min-width="120">
        <template #default="{ row }">{{ AUTH_MODE_LABELS[row.auth_mode as AuthMode] || row.auth_mode }}</template>
      </el-table-column>
      <el-table-column label="TOTP" min-width="80">
        <template #default="{ row }">
          <el-tag :type="row.totp_enabled ? 'success' : 'info'" size="small" effect="plain">
            {{ row.totp_enabled ? '已启用' : '未启用' }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column label="状态" min-width="70">
        <template #default="{ row }">
          <el-tag :type="row.is_active ? 'success' : 'danger'" size="small">
            {{ row.is_active ? '启用' : '禁用' }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column label="最近登录" min-width="180">
        <template #default="{ row }">
          <span class="font-mono">{{ formatTime(row.last_login_at) }}</span>
        </template>
      </el-table-column>
      <el-table-column label="操作" width="170">
        <template #default="{ row }">
          <div class="action-buttons">
            <el-button text size="small" :icon="Edit" @click="openEditDialog(row)">编辑</el-button>
            <el-button text size="small" type="danger" :icon="Delete" @click="handleDelete(row)">删除</el-button>
          </div>
        </template>
      </el-table-column>
    </el-table>

    <!-- 新建用户 -->
    <el-dialog v-model="createDialogVisible" title="新建用户" width="440px">
      <el-form label-width="90px">
        <el-form-item label="用户名">
          <el-input v-model="createForm.username" placeholder="请输入用户名" />
        </el-form-item>
        <el-form-item v-if="createForm.auth_mode !== 'TOTP_ONLY'" label="密码">
          <el-input v-model="createForm.password" type="password" show-password placeholder="至少 8 位" />
        </el-form-item>
        <el-form-item label="角色">
          <el-select v-model="createForm.role" class="full-width">
            <el-option label="普通用户" value="user" />
            <el-option label="管理员" value="admin" />
          </el-select>
        </el-form-item>
        <el-form-item label="认证模式">
          <el-select v-model="createForm.auth_mode" class="full-width">
            <el-option label="仅密码" value="PASSWORD_ONLY" />
            <el-option label="仅 TOTP" value="TOTP_ONLY" />
            <el-option label="密码 + TOTP" value="PASSWORD_AND_TOTP" />
          </el-select>
        </el-form-item>
        <div v-if="createForm.auth_mode !== 'PASSWORD_ONLY'" class="create-totp-hint">
          创建后将自动生成 TOTP 密钥并显示二维码
        </div>
      </el-form>
      <template #footer>
        <el-button @click="createDialogVisible = false">取消</el-button>
        <el-button type="primary" @click="handleCreate">创建</el-button>
      </template>
    </el-dialog>

    <!-- 编辑用户（含密码重置 + TOTP 管理） -->
    <el-dialog v-model="editDialogVisible" title="编辑用户" width="460px">
      <el-form v-if="editForm && editUser" label-width="90px" label-position="left">
        <el-form-item label="角色">
          <el-select v-model="editForm.role" class="full-width">
            <el-option label="普通用户" value="user" />
            <el-option label="管理员" value="admin" />
          </el-select>
        </el-form-item>
        <el-form-item label="认证模式">
          <el-select v-model="editForm.auth_mode" class="full-width">
            <el-option label="仅密码" value="PASSWORD_ONLY" />
            <el-option label="仅 TOTP" value="TOTP_ONLY" />
            <el-option label="密码 + TOTP" value="PASSWORD_AND_TOTP" />
          </el-select>
        </el-form-item>
        <el-form-item label="账号状态">
          <el-switch v-model="editForm.is_active" active-text="启用" inactive-text="禁用" />
        </el-form-item>
        <el-form-item label="新密码">
          <el-input v-model="editForm.new_password" type="password" show-password placeholder="留空不修改密码" />
        </el-form-item>
        <el-form-item label="TOTP">
          <div class="edit-totp-actions">
            <el-button v-if="!editForm.totp_enabled" text size="small" type="success" @click="handleEnableTotp(editUser)">启用 TOTP</el-button>
            <template v-else>
              <el-button text size="small" type="primary" @click="handleViewTotp(editUser)">查看 TOTP</el-button>
              <el-button text size="small" type="warning" @click="handleDisableTotp(editUser)">禁用 TOTP</el-button>
            </template>
          </div>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="editDialogVisible = false">取消</el-button>
        <el-button type="primary" @click="handleEdit">保存</el-button>
      </template>
    </el-dialog>

    <!-- TOTP 绑定信息（含二维码） -->
    <el-dialog v-model="totpDialogVisible" :title="totpDialogTitle" width="480px">
      <div v-if="totpResult" class="totp-info">
        <div class="totp-qr-wrapper">
          <img v-if="qrDataUrl" :src="qrDataUrl" alt="TOTP QR Code" class="totp-qr" />
          <div v-else class="totp-qr-placeholder">二维码生成中...</div>
        </div>
        <p class="totp-tip">用认证器 App 扫描上方二维码，或手动输入密钥：</p>
        <div class="totp-secret-row">
          <code class="totp-secret">{{ totpResult.secret }}</code>
          <el-button text size="small" @click="copyToClipboard(totpResult.secret)">复制</el-button>
        </div>
        <details class="totp-uri-details">
          <summary class="totp-uri-label">otpauth URI（备用）</summary>
          <div class="totp-secret-row">
            <code class="totp-uri">{{ totpResult.uri }}</code>
            <el-button text size="small" @click="copyToClipboard(totpResult.uri)">复制</el-button>
          </div>
        </details>
      </div>
      <template #footer>
        <el-button type="primary" @click="totpDialogVisible = false">我已绑定</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<style scoped lang="scss">
.user-manage {
  padding: 4px 0;
}

.toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 16px;

  .toolbar-left {
    display: flex;
    align-items: center;
    gap: 12px;
  }

  .search-input {
    width: 240px;
  }
}

.user-table {
  width: 100%;

  :deep(.el-table__cell) {
    padding: 10px 0;
  }

  :deep(.el-table__header .cell) {
    font-size: 14px;
    font-weight: 700;
    color: $color-primary;
    padding: 0 12px;
  }

  :deep(.el-table__body .cell) {
    font-size: 14px;
    font-weight: 600;
    font-family: $font-mono;
    font-feature-settings: 'tnum';
    padding: 0 12px;
  }

  :deep(.el-button) {
    font-weight: 600;
  }

  :deep(.el-tag) {
    font-weight: 600;
    font-family: $font-mono;
    font-feature-settings: 'tnum';
  }
}

.full-width {
  width: 100%;
}

.edit-totp-actions {
  display: flex;
  gap: 8px;
}

.action-buttons {
  display: flex;
  gap: 4px;
  white-space: nowrap;
}

.create-totp-hint {
  margin-top: 8px;
  padding: 8px 12px;
  background: var(--el-color-warning-light-9);
  border-radius: 4px;
  font-size: 13px;
  color: var(--el-color-warning-dark-2);
}

.totp-info {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 12px;

  .totp-qr-wrapper {
    display: flex;
    justify-content: center;
    padding: 12px;
    background: #fff;
    border: 1px solid #e4e7ed;
    border-radius: 8px;
  }

  .totp-qr {
    width: 220px;
    height: 220px;
  }

  .totp-qr-placeholder {
    width: 220px;
    height: 220px;
    display: flex;
    align-items: center;
    justify-content: center;
    color: #909399;
    font-size: 14px;
  }

  .totp-tip {
    font-size: 13px;
    color: $color-text-regular;
    margin: 0;
    text-align: center;
  }

  .totp-secret-row {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 10px 12px;
    background: $color-bg-inset;
    border-radius: $radius-md;
    width: 100%;
    box-sizing: border-box;
  }

  .totp-secret {
    font-family: $font-mono;
    font-size: 18px;
    font-weight: 700;
    color: $color-primary;
    letter-spacing: 2px;
    word-break: break-all;
    flex: 1;
  }

  .totp-uri-details {
    width: 100%;

    .totp-uri-label {
      font-size: 12px;
      color: $color-text-secondary;
      cursor: pointer;
      margin-bottom: 6px;
    }
  }

  .totp-uri {
    font-family: $font-mono;
    font-size: 11px;
    color: $color-text-secondary;
    word-break: break-all;
    flex: 1;
  }
}
</style>
