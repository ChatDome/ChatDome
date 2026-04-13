import json
import logging
import os
import time
from typing import Dict, TypedDict

logger = logging.getLogger(__name__)

# Constants
DATA_DIR = "chat_data"
USAGE_FILE = f"{DATA_DIR}/token_usage.jsonl"


class TokenStats(TypedDict):
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int


class TokenTracker:
    """
    Centralized tracker for LLM token usage.
    Logs each inference call into a JSON Lines (.jsonl) file for future web GUI analysis
    and provides local aggregation queries.
    """

    @classmethod
    def record_usage(
        cls, 
        chat_id: int, 
        model: str, 
        action: str, 
        prompt_tokens: int, 
        completion_tokens: int,
        total_tokens: int
    ) -> None:
        """Append token usage details to the persistent JSON Lines log."""
        os.makedirs(DATA_DIR, exist_ok=True)
        
        record = {
            "timestamp": int(time.time()),
            "chat_id": chat_id,
            "model": model,
            "action": action,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": total_tokens
        }
        
        try:
            with open(USAGE_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
        except Exception as e:
            logger.error("Failed to write token usage log: %s", e)

    @classmethod
    def get_user_stats(cls, chat_id: int) -> TokenStats:
        """Aggregates summary statistics for a specific chat_id by scanning the JSONL file."""
        stats: TokenStats = {
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0
        }
        
        if not os.path.exists(USAGE_FILE):
            return stats
            
        try:
            with open(USAGE_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        if data.get("chat_id") == chat_id:
                            stats["prompt_tokens"] += int(data.get("prompt_tokens", 0))
                            stats["completion_tokens"] += int(data.get("completion_tokens", 0))
                            stats["total_tokens"] += int(data.get("total_tokens", 0))
                    except json.JSONDecodeError:
                        # Ignore malformed lines if the file got externally corrupted
                        pass
        except Exception as e:
            logger.error("Failed to read token usage log: %s", e)
            
        return stats
