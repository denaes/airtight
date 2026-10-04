const systemPrompt = `You are an assistant. ${userInput}`;
const system_prompt = f"You are an assistant. Answer using: {user_input}";
const conf = { system: `You are an assistant. Context: ${req.body.context}` };
const msg = { role: "system", content: `You are a bot. ${query}` };
