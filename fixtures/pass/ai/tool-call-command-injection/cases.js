child_process.execFile('/usr/bin/git', ['status'], callback);
subprocess.run(['git', 'status'], shell=False);
// child_process.exec(toolCall.arguments.command);
handleTool(toolCall.arguments.command);
const query = sanitizeInput(toolCall.arguments.query);
executeDatabaseQuery(query);
