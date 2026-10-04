const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
const siteUrl = process.env.NEXT_PUBLIC_SITE_URL;
const appTitle = import.meta.env.VITE_APP_TITLE;
const token = window.sessionStorage.getItem("token");
