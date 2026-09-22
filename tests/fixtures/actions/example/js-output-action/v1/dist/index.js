"use strict";
const core = require("@actions/core");
const { spawn } = require("node:child_process");

const prompt = core.getInput("prompt");
core.setOutput("result", prompt);
spawn("tool", ["--prompt", prompt], { stdio: "inherit" });
