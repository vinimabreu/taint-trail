"use strict";
const core = require("@actions/core");
const { execFile } = require("node:child_process");

const target = core.getInput("target");
execFile("ls", ["-la", target], (error, stdout) => {
  if (error) {
    core.setFailed(error.message);
    return;
  }
  core.info(stdout);
});
