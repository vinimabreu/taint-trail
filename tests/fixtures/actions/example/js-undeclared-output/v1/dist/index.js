const core = require("@actions/core");
core.setOutput("secret", process.env.HELPER_PROMPT);
