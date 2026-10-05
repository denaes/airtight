'use server';

import { db } from '@/lib/db';
import { prisma } from '@/lib/prisma';
import { auth } from '@/auth';

export async function deleteProjectSafe(projectId: string) {
  const session = await auth();
  if (!session?.user) throw new Error('Unauthorized');
  await db.project.delete({ where: { id: projectId } });
}

export async function updateUserRoleSafe(userId: string, role: string) {
  const session = await auth();
  if (!session?.user?.isAdmin) throw new Error('Forbidden');
  await prisma.user.update({ where: { id: userId }, data: { role } });
}

export async function getProject(projectId: string) {
  return await db.project.findUnique({ where: { id: projectId } });
}
