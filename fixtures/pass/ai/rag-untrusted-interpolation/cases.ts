const systemPrompt = `You are an assistant. <context>${userInput}</context>`;
const system_prompt = f"""You are an assistant. {user_input}"""
const conf = { system: `[CONTEXT]${input}[/CONTEXT]` };
const staticPrompt = "You are a helpful assistant.";
const userMsg = { role: "user", content: userInput };
