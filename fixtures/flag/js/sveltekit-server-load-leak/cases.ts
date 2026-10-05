import { db } from '$lib/server/db';
import { prisma } from '$lib/server/prisma';
import { pool } from '$lib/server/pool';

// Shape 1: Unfiltered prisma findMany returning all users
export const load = async () => {
  const users = await prisma.user.findMany();
  return { users };
};

// Shape 2: Raw SQL query selecting sensitive accounts without session filter
export async function loadAccounts() {
  const accounts = await db.query('SELECT * FROM accounts');
  return { accounts };
}

// Shape 3: Direct return of apiKeys without tenancy check
export const loadKeys = async () => {
  return {
    apiKeys: await prisma.apiKey.findMany()
  };
};

// Shape 4: Raw SQL selecting billing table without authorization
export async function loadBilling({ params }) {
  const billing = await pool.query('SELECT * FROM billing');
  return { billing };
}
