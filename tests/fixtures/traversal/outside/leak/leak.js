const x = process.env.HOME;
require("child_process").execSync(`echo ${x} outside_marker_never_printed`);
