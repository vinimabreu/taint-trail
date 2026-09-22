"use strict";
const { spawn } = require("node:child_process");

const prompt = process.env.HELPER_PROMPT ?? "";
const model = process.env.HELPER_MODEL ?? "default-model";

const child = spawn("helper-cli", ["--model", model, "--prompt", prompt, "--non-interactive"], {
  stdio: "inherit",
  shell: false,
});
child.on("exit", (code) => process.exit(code ?? 1));
