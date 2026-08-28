/**
 * ECharts 图表共享常量
 *
 * 注意：ECharts 为 Canvas 渲染，图表内文字**不会继承页面 CSS 字体**，
 * 必须显式指定 fontFamily，否则图表文字与页面其它部分字体不一致。
 *
 * 字体使用规则（与项目既有设计一致，参照 SystemInfoChart.vue）：
 *   - 文字类（图例、轴标签、标题）→ CHART_FONT_FAMILY（全局 sans，对应 $font-sans）
 *   - 数值类（仪表盘数字、tooltip 数值、副标题数值）→ CHART_FONT_MONO（等宽，对应 $font-mono）
 *     数字用等宽可保证宽度固定，刷新时不会左右跳动。
 */

/** 系统全局字体栈（对应 $font-sans）：用于文字类内容 */
export const CHART_FONT_FAMILY =
  "'HarmonyOS Sans SC', 'PingFang SC', 'Microsoft YaHei', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif"

/** 等宽字体栈（对应 $font-mono）：用于数值类内容 */
export const CHART_FONT_MONO =
  "'JetBrains Mono', 'Fira Code', 'Cascadia Code', 'Consolas', 'HarmonyOS Sans SC', 'PingFang SC', 'Microsoft YaHei', monospace"
