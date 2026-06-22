"""Stage 4: RAG 知识检索

从本地知识库检索与当前告警相关的安全知识。
支持按 MITRE ID、SOC 分类、签名关键词匹配。

知识库目录结构：
    knowledge/
    ├── mitre-attack/     # MITRE ATT&CK 技术说明 (.md)
    ├── soc-playbook/     # SOC 处置手册 (.md)
    └── suricata-rules/   # Suricata 规则说明 (.md)

后续可升级为向量检索（ChromaDB + Embedding）。
"""

import logging
from pathlib import Path
from langchain_core.runnables import RunnableLambda

logger = logging.getLogger(__name__)


class KnowledgeRetriever:
    """安全知识库检索器

    根据告警的 MITRE ID、SOC 分类、签名关键词，
    从本地知识文件中检索相关安全知识。
    """

    def __init__(self, knowledge_dir: str = None):
        self.knowledge_dir = Path(knowledge_dir) if knowledge_dir else None
        self._cache = {}  # 文件路径 -> 内容缓存

        if self.knowledge_dir and self.knowledge_dir.exists():
            file_count = sum(1 for _ in self.knowledge_dir.rglob("*.md"))
            logger.info("知识库目录: %s (%d 个 .md 文件)", self.knowledge_dir, file_count)
        else:
            logger.warning("知识库目录不存在: %s", self.knowledge_dir)

    def retrieve(self, ctx) -> str:
        """根据告警上下文检索相关知识

        Args:
            ctx: AlertContext 对象（或包含 mitre_id/soc_category/signature 的对象）

        Returns:
            拼接的知识文本
        """
        if not self.knowledge_dir or not self.knowledge_dir.exists():
            return "无可用知识库"

        snippets = []

        # 1. 按 MITRE ID 检索技术说明
        mitre_id = getattr(ctx, "mitre_id", "")
        if mitre_id:
            content = self._load_file(f"mitre-attack/{mitre_id}.md")
            if content:
                snippets.append(f"### MITRE ATT&CK {mitre_id}\n{content}")

        # 2. 按 SOC 分类检索处置手册
        soc_category = getattr(ctx, "soc_category", "")
        if soc_category:
            content = self._load_file(f"soc-playbook/{soc_category}.md")
            if content:
                snippets.append(f"### SOC 处置手册: {soc_category}\n{content}")

        # 3. 按签名关键词检索规则说明
        signature = getattr(ctx, "signature", "")
        if signature:
            content = self._search_rules(signature)
            if content:
                snippets.append(f"### 规则参考\n{content}")

        if not snippets:
            return "未检索到相关知识"

        return "\n\n---\n\n".join(snippets)

    def _load_file(self, relative_path: str) -> str:
        """加载知识文件（带缓存）"""
        if relative_path in self._cache:
            return self._cache[relative_path]

        filepath = self.knowledge_dir / relative_path
        if filepath.exists():
            content = filepath.read_text(encoding="utf-8")
            self._cache[relative_path] = content
            return content
        return ""

    def _search_rules(self, signature: str) -> str:
        """在 suricata-rules 目录中搜索匹配的规则说明"""
        rules_dir = self.knowledge_dir / "suricata-rules"
        if not rules_dir.exists():
            return ""

        sig_lower = signature.lower()
        # 提取签名中的关键词（长度>3的词）
        keywords = [w for w in sig_lower.split() if len(w) > 3]

        results = []
        for f in rules_dir.glob("*.md"):
            content = f.read_text(encoding="utf-8")
            content_lower = content.lower()
            # 简单关键词匹配
            if sig_lower in content_lower or any(kw in content_lower for kw in keywords):
                results.append(content[:500])

        return "\n---\n".join(results[:3]) if results else ""


def create_knowledge_retriever(knowledge_dir: str = None) -> RunnableLambda:
    """创建知识检索 Runnable"""
    retriever = KnowledgeRetriever(knowledge_dir)
    return RunnableLambda(retriever.retrieve)
