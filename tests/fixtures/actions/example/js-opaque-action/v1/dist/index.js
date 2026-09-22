"use strict";
const core = require("@actions/core");
const fs = require("node:fs");

const note = core.getInput("note");
fs.writeFileSync("note.txt", note, "utf8");
core.info("note written");
