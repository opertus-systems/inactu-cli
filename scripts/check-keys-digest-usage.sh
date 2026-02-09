#!/usr/bin/env bash
set -euo pipefail

files=(
  "README.md"
  "Makefile"
  "cli/provenact-cli/README.md"
  "docs/*.md"
  ".github/workflows/*.yml"
)

awk '
function is_verify_run_command(s) {
  return s ~ /provenact-cli[[:space:]]+(verify|run)([[:space:]]|$)/ || s ~ /cargo[[:space:]]+run[[:space:]]+-p[[:space:]]+provenact-cli[[:space:]]+--[[:space:]]+(verify|run)([[:space:]]|$)/ || s ~ /\$\(CLI\)[[:space:]]+(verify|run)([[:space:]]|$)/;
}

function flush_command() {
  if (!active) {
    return;
  }
  normalized = command_buf;
  gsub(/[[:space:]]+/, " ", normalized);
  if (normalized !~ /--keys-digest([[:space:]]|$)/) {
    printf "%s:%d: verify/run command missing --keys-digest\n", command_file, command_line > "/dev/stderr";
    errors = 1;
  }
  active = 0;
  command_buf = "";
  command_file = "";
  command_line = 0;
}

{
  line = $0;

  if (active) {
    command_buf = command_buf " " line;
    if (line ~ /\\[[:space:]]*$/) {
      next;
    }
    flush_command();
    next;
  }

  if (is_verify_run_command(line)) {
    active = 1;
    command_buf = line;
    command_file = FILENAME;
    command_line = FNR;
    if (line !~ /\\[[:space:]]*$/) {
      flush_command();
    }
  }
}

END {
  flush_command();
  exit errors;
}
' ${files[@]}

echo "OK keys-digest usage gate"
