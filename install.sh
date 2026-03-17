#!/bin/bash
# Claude Bug Bounty — install skills into ~/.claude/skills/

set -e

INSTALL_DIR="${HOME}/.claude/skills"
mkdir -p "${INSTALL_DIR}"

echo "Installing Claude Bug Bounty skills..."
echo ""

# Copy all skills
for skill_dir in skills/*/; do
    skill_name=$(basename "$skill_dir")
    mkdir -p "${INSTALL_DIR}/${skill_name}"
    cp "${skill_dir}SKILL.md" "${INSTALL_DIR}/${skill_name}/SKILL.md"
    echo "✓ Installed skill: ${skill_name}"
done

# Install commands
COMMANDS_DIR="${HOME}/.claude/commands"
mkdir -p "${COMMANDS_DIR}"

for cmd_file in commands/*.md; do
    cmd_name=$(basename "$cmd_file")
    cp "$cmd_file" "${COMMANDS_DIR}/${cmd_name}"
    echo "✓ Installed command: ${cmd_name}"
done

echo ""
echo "Done! Skills installed to ${INSTALL_DIR}"
echo "Commands installed to ${COMMANDS_DIR}"
echo ""
echo "Start hunting:"
echo "  claude"
echo "  /recon target.com"
echo "  /hunt target.com"
