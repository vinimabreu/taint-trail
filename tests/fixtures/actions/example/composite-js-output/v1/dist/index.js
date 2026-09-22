"use strict";
const fs = require("node:fs");
const { spawn } = require("node:child_process");

const prompt = process.env.PROMPT ?? "";
fs.appendFileSync(process.env.GITHUB_OUTPUT, `result=${prompt}\n`);
spawn("tool", ["--prompt", prompt], { stdio: "inherit" });
