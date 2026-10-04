eval(completion.choices[0].message.content);
eval(response.content);
new Function(aiResponse)();
exec(llm_output);
