import json
import logging
import os
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Union

logger = logging.getLogger(__name__)

# Basic stop words for simple keyword extraction (Chinese & English)
STOP_WORDS = {
    "的", "了", "和", "是", "就", "都", "而", "及", "与", "着",
    "或", "一个", "没有", "我们", "你们", "他们", "它", "这", "那",
    "在", "关于", "对于", "把", "被", "向", "从", "到", "让",
    "the", "is", "a", "an", "and", "or", "to", "in", "on", "with",
    "for", "of", "at", "by", "this", "that", "it", "we", "they", "you",
    "不要", "不能", "必须", "需要", "应该"
}

# Conflict signal words to increase conflict probability
CONFLICT_SIGNALS = {
    "不用", "使用", "禁止", "允许", "关闭", "开启", 
    "改用", "继续用", "停用", "启用", "移除", "安装",
    "不", "没", "不是"
}

@dataclass
class Engram:
    """Represents a single piece of persistent memory (Engram)."""
    id: str
    category: str
    fact: str
    source_context: str
    created_at: float
    superseded_by: Optional[str] = None


class EngramStore:
    """
    Manages persistent Host Knowledge Base (Engrams).
    Stores data globally in a single JSON file.
    """
    MAX_PROMPT_ENTRIES = 30

    def __init__(self, storage_path: Union[str, Path] = "chat_data/engram.json"):
        self.storage_path = Path(storage_path)
        self._engrams: Dict[str, Engram] = {}
        self._load()

    def _load(self):
        """Loads engrams from disk."""
        if not self.storage_path.exists():
            return
            
        try:
            with open(self.storage_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                for item in data:
                    engram = Engram(**item)
                    self._engrams[engram.id] = engram
        except Exception as e:
            logger.error(f"Failed to load EngramStore from {self.storage_path}: {e}")

    def _save(self):
        """Saves engrams to disk."""
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with open(self.storage_path, 'w', encoding='utf-8') as f:
                data = [asdict(e) for e in self._engrams.values()]
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"Failed to save EngramStore to {self.storage_path}: {e}")

    def add(self, category: str, fact: str, source_context: str) -> Engram:
        """Adds a new Engram."""
        import uuid
        engram_id = f"eg-{int(time.time() * 1000)}-{uuid.uuid4().hex[:6]}"
        engram = Engram(
            id=engram_id,
            category=category,
            fact=fact,
            source_context=source_context,
            created_at=time.time(),
            superseded_by=None
        )
        self._engrams[engram_id] = engram
        self._save()
        return engram

    def list(self, category: Optional[str] = None, include_superseded: bool = False) -> List[Engram]:
        """Lists engrams, sorted by creation time descending."""
        results = []
        for e in self._engrams.values():
            if category and e.category != category:
                continue
            if not include_superseded and e.superseded_by is not None:
                continue
            results.append(e)
            
        results.sort(key=lambda x: x.created_at, reverse=True)
        return results

    def supersede(self, old_id: str, new_category: str, new_fact: str, source_context: str) -> Engram:
        """Supersedes an existing Engram with a new one."""
        if old_id not in self._engrams:
            raise ValueError(f"Engram {old_id} not found")
            
        new_engram = self.add(new_category, new_fact, source_context)
        self._engrams[old_id].superseded_by = new_engram.id
        self._save()
        return new_engram

    def remove(self, engram_id: str) -> bool:
        """Permanently removes an Engram."""
        if engram_id in self._engrams:
            del self._engrams[engram_id]
            self._save()
            return True
        return False

    def build_engram_prompt(self) -> str:
        """Builds the string to be injected into the LLM System Prompt."""
        active_engrams = self.list(include_superseded=False)
        if not active_engrams:
            return ""

        # Limit to the most recent MAX_PROMPT_ENTRIES
        selected = active_engrams[:self.MAX_PROMPT_ENTRIES]
        
        lines = [
            "[Engram — 记忆印迹]",
            "以下是用户明确声明的主机环境事实、运维偏好和操作约束。",
            "这些信息优先于任何推测，必须在相关操作中严格遵循。"
        ]
        
        # Sort ascending for prompt so oldest is first, newest at the bottom
        selected.sort(key=lambda x: x.created_at)
        
        for e in selected:
            lines.append(f"- [{e.category}] {e.fact}")
            
        return "\n".join(lines) + "\n"

    def _extract_keywords(self, text: str) -> Set[str]:
        """Simple bigram and unigram extraction for conflict detection without heavy NLP."""
        text = text.lower()
        words = set()
        
        # Extract English words
        import re
        en_words = re.findall(r'\b[a-z0-9_-]+\b', text)
        for w in en_words:
            if w not in STOP_WORDS:
                words.add(w)
                
        # Extract Chinese chars
        zh_chars = re.findall(r'[\u4e00-\u9fa5]', text)
        # Filter out stopwords first so we don't form n-grams with them
        valid_chars = [c for c in zh_chars if c not in STOP_WORDS]
        
        # Add bigrams
        for i in range(len(valid_chars) - 1):
            words.add(valid_chars[i] + valid_chars[i+1])
        # Add trigrams
        for i in range(len(valid_chars) - 2):
            words.add(valid_chars[i] + valid_chars[i+1] + valid_chars[i+2])
                    
        return words

    def find_conflicts(self, category: str, new_fact: str) -> List[Engram]:
        """
        Detects if a new fact conflicts with any existing active engrams in the same category.
        Uses a heuristic based on keyword overlap and conflict signal words.
        """
        active_engrams = self.list(category=category, include_superseded=False)
        if not active_engrams:
            return []
            
        new_keywords = self._extract_keywords(new_fact)
        if not new_keywords:
            return []
            
        has_signal = any(signal in new_fact for signal in CONFLICT_SIGNALS)
        
        conflicts = []
        for e in active_engrams:
            old_keywords = self._extract_keywords(e.fact)
            if not old_keywords:
                continue
                
            intersection = new_keywords.intersection(old_keywords)
            # Calculate Jaccard similarity
            union = new_keywords.union(old_keywords)
            similarity = len(intersection) / len(union) if union else 0
            
            # Heuristic: If they share significant nouns/entities (high similarity) 
            # and there's a conflict signal, OR they share > 50% keywords.
            # We tune this to be sensitive enough to ask the user, but not annoying.
            if similarity > 0.4 or (similarity > 0.2 and has_signal) or len(intersection) >= 3:
                # Also check if it's literally the same fact
                if new_fact.strip() != e.fact.strip():
                    conflicts.append(e)
                    
        return conflicts
