"use strict";
const core = require("@actions/core");
const { execSync } = require("node:child_process");

const message = core.getInput("message");
const printed = execSync(`echo "${message}" | tee /tmp/message.txt`).toString();
core.setOutput("echoed", printed.trim());
