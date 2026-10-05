import { exec, execSync } from 'node:child_process';
import fs from 'node:fs';

export default defineEventHandler(async (event) => {
  // Shape 1: Direct template interpolation in database query
  await db.query(`SELECT * FROM users WHERE email = '${(await readBody(event)).email}'`);

  // Shape 2: Direct string concatenation in pool query
  await pool.query("SELECT * FROM items WHERE tag = '" + (await readBody(event)).tag + "'");

  // Shape 3: Direct interpolation in shell command
  exec(`git checkout ${(await readBody(event)).branch}`);

  // Shape 4: Direct interpolation in file write
  fs.writeFileSync(`/tmp/${(await readBody(event)).filename}`, 'data');

  // Shape 5: Direct concatenation in execSync
  execSync("echo " + (await readBody(event)).payload);

  // Shape 6: Direct interpolation in prisma raw query
  await prisma.$queryRawUnsafe(`SELECT * FROM accounts WHERE id = ${(await readBody(event)).id}`);
});
