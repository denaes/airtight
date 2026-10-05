import { execFile, spawn } from 'node:child_process';
import fs from 'node:fs';

export default defineEventHandler(async (event) => {
  // Near-miss 1: Parameterized SQL query passing value in params array
  await db.query('SELECT * FROM users WHERE email = $1', [(await readBody(event)).email]);

  // Near-miss 2: Safe execFile with arguments array
  execFile('git', ['checkout', (await readBody(event)).branch]);

  // Near-miss 3: Runtime schema validation before handling
  const body = userSchema.parse(await readBody(event));

  // Near-miss 4: Returning parsed body without dangerous sink
  const data = await readBody(event);
  console.log('Received body', data);

  // Near-miss 5: ORM query with parameterized criteria
  await knex('items').where({ tag: (await readBody(event)).tag });

  // Near-miss 6: File read of constant path
  const config = fs.readFileSync('/etc/app.conf', 'utf8');

  return { status: 'ok' };
});
