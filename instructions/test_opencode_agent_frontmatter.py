from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
AGENTS_DIR = REPO_ROOT / "agents"


def _frontmatter_lines(path: Path) -> list[str]:
    lines = path.read_text(encoding="utf-8").splitlines()
    assert lines[0] == "---"
    end = lines.index("---", 1)
    return lines[1:end]


def _tools_mapping(path: Path) -> dict[str, bool]:
    lines = _frontmatter_lines(path)
    tools_index = lines.index("tools:")
    tools = {}

    for line in lines[tools_index + 1 :]:
        if not line.startswith("  "):
            break
        name, value = line.strip().split(":", 1)
        assert value.strip() in {"true", "false"}
        tools[name] = value.strip() == "true"

    return tools


def test_agent_tools_use_opencode_mapping_schema():
    agent_files = [
        path
        for path in sorted(AGENTS_DIR.glob("*.md"))
        if path.read_text(encoding="utf-8").startswith("---\n")
    ]
    assert agent_files

    for path in agent_files:
        tools = _tools_mapping(path)
        assert tools, f"{path.name} must define tools as a mapping"
        assert all(name == name.lower() for name in tools)


def test_credential_hunter_uses_opencode_question_tool():
    tools = _tools_mapping(AGENTS_DIR / "credential-hunter.md")
    assert tools["question"] is True
    assert "askuserquestion" not in tools
