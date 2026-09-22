"use strict";
const core = require("@actions/core");
const { exec } = require("node:child_process");

const directory = core.getInput("directory");
exec(`du -sh ${directory}`, (error, stdout) => {
  if (error) {
    core.setFailed(error.message);
    return;
  }
  core.info(stdout);
});
