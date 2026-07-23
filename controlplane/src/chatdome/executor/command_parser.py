"""Shell command segmentation helpers used by approval analysis."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ShellCommandSegment:
    """One command and the separator that follows it."""

    command: str
    separator: str = ""


@dataclass
class _ParserFrame:
    kind: str
    closing: str = ""
    quote: str = ""
    escaped: bool = False
    in_comment: bool = False


def _starts_comment(command: str, index: int) -> bool:
    if index == 0:
        return True
    previous = command[index - 1]
    return previous.isspace() or previous in ";|&(){}"


def _is_reserved_brace(command: str, index: int) -> bool:
    previous = command[index - 1] if index > 0 else ""
    following = command[index + 1] if index + 1 < len(command) else ""
    left_boundary = not previous or previous.isspace() or previous in ";|&()"
    right_boundary = not following or following.isspace() or following in ";|&()"
    return left_boundary and right_boundary


def _has_compound_keywords(words: set[str]) -> bool:
    if {"if", "fi"} <= words or {"case", "esac"} <= words:
        return True
    loop_starts = {"for", "while", "until", "select"}
    return bool(words & loop_starts) and {"do", "done"} <= words


def split_shell_commands(command: str) -> tuple[ShellCommandSegment, ...]:
    """Split a Bash command at unquoted top-level semicolons."""

    text = str(command or "")
    if not text.strip():
        return ()

    segments: list[ShellCommandSegment] = []
    frames = [_ParserFrame(kind="root")]
    root_words: set[str] = set()
    root_word: list[str] = []
    start = 0
    index = 0
    invalid_structure = False
    heredoc_detected = False

    def flush_root_word() -> None:
        if root_word:
            root_words.add("".join(root_word))
            root_word.clear()

    while index < len(text):
        frame = frames[-1]
        character = text[index]

        if frame.in_comment:
            if character in "\r\n":
                frame.in_comment = False
            index += 1
            continue

        if frame.escaped:
            frame.escaped = False
            index += 1
            continue

        if frame.quote == "'":
            if character == "'":
                frame.quote = ""
            index += 1
            continue
        if frame.quote == "ansi_single":
            if character == "\\":
                frame.escaped = True
            elif character == "'":
                frame.quote = ""
            index += 1
            continue

        if frame.quote == '"':
            if character == "\\":
                frame.escaped = True
                index += 1
                continue
            if character == '"':
                frame.quote = ""
                index += 1
                continue
            if character == "$" and index + 1 < len(text) and text[index + 1] in "({":
                opening = text[index + 1]
                kind = "command" if opening == "(" else "parameter"
                frames.append(_ParserFrame(kind=kind, closing=")" if opening == "(" else "}"))
                index += 2
                continue
            if character == "`":
                frames.append(_ParserFrame(kind="backtick", closing="`"))
            index += 1
            continue

        if frame.kind == "backtick" and character == "`":
            frames.pop()
            index += 1
            continue
        if character == "\\":
            if len(frames) == 1:
                flush_root_word()
            frame.escaped = True
            index += 1
            continue
        if character == "$" and index + 1 < len(text) and text[index + 1] == "'":
            if len(frames) == 1:
                flush_root_word()
            frame.quote = "ansi_single"
            index += 2
            continue
        if character in {"'", '"'}:
            if len(frames) == 1:
                flush_root_word()
            frame.quote = character
            index += 1
            continue
        if character == "$" and index + 1 < len(text) and text[index + 1] in "({":
            if len(frames) == 1:
                flush_root_word()
            opening = text[index + 1]
            kind = "command" if opening == "(" else "parameter"
            frames.append(_ParserFrame(kind=kind, closing=")" if opening == "(" else "}"))
            index += 2
            continue
        if character == "`":
            if len(frames) == 1:
                flush_root_word()
            frames.append(_ParserFrame(kind="backtick", closing="`"))
            index += 1
            continue
        if character == "#" and frame.kind != "parameter" and _starts_comment(text, index):
            if len(frames) == 1:
                flush_root_word()
            frame.in_comment = True
            index += 1
            continue
        if frame.closing and character == frame.closing:
            if frame.kind != "brace_group" or _is_reserved_brace(text, index):
                frames.pop()
                index += 1
                continue
        if character == "(":
            if len(frames) == 1:
                flush_root_word()
            frames.append(_ParserFrame(kind="parenthesis", closing=")"))
            index += 1
            continue
        if character == ")" and len(frames) == 1:
            invalid_structure = True
            index += 1
            continue
        if character == "{" and _is_reserved_brace(text, index):
            if len(frames) == 1:
                flush_root_word()
            frames.append(_ParserFrame(kind="brace_group", closing="}"))
            index += 1
            continue
        if (
            character == "<"
            and (index == 0 or text[index - 1] != "<")
            and text.startswith("<<", index)
            and not text.startswith("<<<", index)
        ):
            heredoc_detected = True

        if len(frames) == 1:
            if character.isspace() or character in ";|&()<>{}":
                flush_root_word()
            else:
                root_word.append(character)

        if character == ";" and len(frames) == 1:
            previous = text[index - 1] if index > 0 else ""
            following = text[index + 1] if index + 1 < len(text) else ""
            if previous != ";" and following not in {";", "&"}:
                child = text[start:index].strip()
                if child:
                    segments.append(ShellCommandSegment(command=child, separator=";"))
                start = index + 1
        index += 1

    flush_root_word()
    root_frame = frames[0]
    if len(frames) != 1 or root_frame.quote or root_frame.escaped:
        invalid_structure = True
    if invalid_structure or heredoc_detected or _has_compound_keywords(root_words):
        return (ShellCommandSegment(command=text.strip()),)

    tail = text[start:].strip()
    if tail:
        segments.append(ShellCommandSegment(command=tail))
    return tuple(segments)
