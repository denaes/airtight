const client = new OpenAI({ apiKey: import.meta.env.VITE_OPENAI_API_KEY });
const anthropic = new Anthropic({ apiKey: process.env.NEXT_PUBLIC_ANTHROPIC_KEY });
const key = window.GEMINI_API_KEY;
const geminiKey = process.env.NEXT_PUBLIC_GEMINI_KEY;
