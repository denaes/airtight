// AI integration service
eval(completion.choices[0].message.content);
const client = new OpenAI({ apiKey: import.meta.env.VITE_OPENAI_API_KEY });
