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


def _is_double_bracket_open(command: str, index: int) -> bool:
    previous = command[index - 1] if index > 0 else ""
    following = command[index + 2] if index + 2 < len(command) else ""
    left_boundary = not previous or previous.isspace() or previous in ";|&("
    right_boundary = not following or following.isspace()
    return left_boundary and right_boundary


def _is_double_bracket_close(command: str, index: int) -> bool:
    previous = command[index - 1] if index > 0 else ""
    following = command[index + 2] if index + 2 < len(command) else ""
    left_boundary = bool(previous and previous.isspace())
    right_boundary = not following or following.isspace() or following in ";|&)"
    return left_boundary and right_boundary


def _has_compound_keywords(
    words: set[str],
    command_words: set[str],
) -> bool:
    if "if" in command_words and "fi" in words:
        return True
    if "case" in command_words and "esac" in words:
        return True
    loop_starts = {"for", "while", "until", "select"}
    return bool(command_words & loop_starts) and {"do", "done"} <= words


def split_shell_commands(command: str) -> tuple[ShellCommandSegment, ...]:
    """Split a Bash command at unquoted top-level sequence operators."""

    text = str(command or "")
    if not text.strip():
        return ()

    segments: list[ShellCommandSegment] = []
    frames = [_ParserFrame(kind="root")]
    root_words: set[str] = set()
    root_command_words: set[str] = set()
    root_word: list[str] = []
    root_expects_command = True
    start = 0
    index = 0
    invalid_structure = False
    invalid_sequence = False
    heredoc_detected = False

    def flush_root_word() -> None:
        nonlocal root_expects_command
        if root_word:
            word = "".join(root_word)
            root_words.add(word)
            if root_expects_command:
                root_command_words.add(word)
                root_expects_command = word == "!"
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
            if text.startswith("$((", index):
                frames.append(_ParserFrame(kind="arithmetic", closing="))"))
                index += 3
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
        if frame.kind == "arithmetic" and text.startswith("))", index):
            frames.pop()
            index += 2
            continue
        if (
            frame.kind == "conditional"
            and text.startswith("]]", index)
            and _is_double_bracket_close(text, index)
        ):
            frames.pop()
            index += 2
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
        if text.startswith("$((", index):
            if len(frames) == 1:
                flush_root_word()
            frames.append(_ParserFrame(kind="arithmetic", closing="))"))
            index += 3
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
        if (
            len(frames) == 1
            and root_expects_command
            and text.startswith("[[", index)
            and _is_double_bracket_open(text, index)
        ):
            flush_root_word()
            root_expects_command = False
            frames.append(_ParserFrame(kind="conditional", closing="]]"))
            index += 2
            continue
        if (
            len(frames) == 1
            and root_expects_command
            and text.startswith("((", index)
        ):
            flush_root_word()
            root_expects_command = False
            frames.append(_ParserFrame(kind="arithmetic", closing="))"))
            index += 2
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
            and not any(item.kind == "arithmetic" for item in frames)
        ):
            heredoc_detected = True

        if len(frames) == 1:
            if character.isspace() or character in ";|&()<>{}":
                flush_root_word()
            else:
                root_word.append(character)

        separator = ""
        separator_width = 0
        if len(frames) == 1 and text.startswith("&&", index):
            separator = "&&"
            separator_width = 2
        elif len(frames) == 1 and text.startswith("||", index):
            separator = "||"
            separator_width = 2
        elif character == ";" and len(frames) == 1:
            previous = text[index - 1] if index > 0 else ""
            following = text[index + 1] if index + 1 < len(text) else ""
            if previous != ";" and following not in {";", "&"}:
                separator = ";"
                separator_width = 1
        if separator:
            child = text[start:index].strip()
            if child:
                segments.append(
                    ShellCommandSegment(command=child, separator=separator)
                )
            else:
                invalid_sequence = True
            root_expects_command = True
            start = index + separator_width
            index += separator_width
            continue
        if len(frames) == 1 and character in "|&":
            root_expects_command = True
        index += 1

    flush_root_word()
    root_frame = frames[0]
    if len(frames) != 1 or root_frame.quote or root_frame.escaped:
        invalid_structure = True

    tail = text[start:].strip()
    if not tail and segments and segments[-1].separator in {"&&", "||"}:
        invalid_sequence = True
    if (
        invalid_structure
        or invalid_sequence
        or heredoc_detected
        or _has_compound_keywords(root_words, root_command_words)
    ):
        return (ShellCommandSegment(command=text.strip()),)

    if tail:
        segments.append(ShellCommandSegment(command=tail))
    return tuple(segments)
