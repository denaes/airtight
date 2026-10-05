import { error, redirect } from '@sveltejs/kit';
import { db } from '$lib/server/db';
import { prisma } from '$lib/server/prisma';
import { ensureUser } from '$lib/server/auth';

// Near-miss 1: Authenticated load checking locals.user and scoping by tenantId
export const load = async ({ locals }) => {
  if (!locals.user) {
    throw error(401, 'Unauthorized');
  }
  const users = await db.query('SELECT * FROM users WHERE tenant_id = $1', [locals.user.tenantId]);
  return { users };
};

// Near-miss 2: Protected load verifying session
export const loadProtected = async ({ locals }) => {
  const session = await locals.getSession();
  if (!session?.user) throw redirect(303, '/login');
  const accounts = await prisma.account.findMany({ where: { userId: session.user.id } });
  return { accounts };
};

// Near-miss 3: Protected load using ensureUser auth guard
export const loadWithGuard = async (event) => {
  const user = await ensureUser(event);
  const billing = await db.query('SELECT * FROM billing WHERE user_id = $1', [user.id]);
  return { billing };
};

// Near-miss 4: Querying a public catalog table without user data
export const loadCatalog = async () => {
  const catalog = await db.query('SELECT * FROM public_catalog');
  return { catalog };
};

// Near-miss 5: Parameterized findUnique for single public item
export const loadArticle = async ({ params }) => {
  const article = await prisma.article.findUnique({ where: { slug: params.slug } });
  return { article };
};
