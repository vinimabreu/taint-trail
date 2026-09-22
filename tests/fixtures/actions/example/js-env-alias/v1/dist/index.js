const core = require("@actions/core");
const env = process.env;
core.setOutput("r", env.HELPER_PROMPT);
