'use server';

import { db } from '@/lib/db';
import { prisma } from '@/lib/prisma';
import fs from 'node:fs';

export async function deleteProject(projectId: string) {
  await db.project.delete({ where: { id: projectId } });
}

export async function updateUserRole(userId: string, role: string) {
  await prisma.user.update({ where: { id: userId }, data: { role } });
}

export async function createPost(title: string, content: string) {
  await db.post.create({ data: { title, content } });
}

export async function writeServerLog(message: string) {
  fs.writeFileSync('/tmp/server.log', message);
}
