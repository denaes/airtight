import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { generateAttackSurfaceMap } from '../engine/src/map.mjs';

function withTempProject(fn) {
  const dir = mkdtempSync(join(tmpdir(), 'airtight-map-test-'));
  try {
    fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test('generateAttackSurfaceMap detects Express routes and sinks', () => {
  withTempProject((root) => {
    mkdirSync(join(root, 'src'), { recursive: true });
    writeFileSync(join(root, 'src/server.js'), `
const express = require('express');
const app = express();
const router = express.Router();

app.get('/api/users', async (req, res) => {
  const rows = await db.query('SELECT * FROM users');
  res.json(rows);
});

router.post('/login', authController.login);

app.use('/admin', adminMiddleware);
    `);

    const result = generateAttackSurfaceMap(['src'], { root });
    assert.equal(result.summary.totalRoutes, 3);
    assert.deepEqual(result.summary.frameworks, ['express']);
    assert.equal(result.summary.totalSinksNearRoutes, 1);

    const [r1, r2, r3] = result.routes;
    assert.equal(r1.method, 'GET');
    assert.equal(r1.path, '/api/users');
    assert.equal(r1.sinks.length, 1);
    assert.equal(r1.sinks[0].type, 'sql');

    assert.equal(r2.method, 'POST');
    assert.equal(r2.path, '/login');
    assert.equal(r2.handlerName, 'authController');

    assert.equal(r3.method, 'USE');
    assert.equal(r3.path, '/admin');
  });
});

test('generateAttackSurfaceMap detects Fastify routes', () => {
  withTempProject((root) => {
    mkdirSync(join(root, 'src'), { recursive: true });
    writeFileSync(join(root, 'src/app.ts'), `
import fastify from 'fastify';
const app = fastify();

app.post('/items', handleCreateItem);

app.route({
  method: 'GET',
  url: '/health',
  handler: healthCheck
});
    `);

    const result = generateAttackSurfaceMap(['src'], { root });
    assert.equal(result.summary.totalRoutes, 2);
    assert.deepEqual(result.summary.frameworks, ['fastify']);

    const [r1, r2] = result.routes;
    assert.equal(r1.method, 'POST');
    assert.equal(r1.path, '/items');
    assert.equal(r1.handlerName, 'handleCreateItem');

    assert.equal(r2.method, 'GET');
    assert.equal(r2.path, '/health');
    assert.equal(r2.handlerName, 'healthCheck');
  });
});

test('generateAttackSurfaceMap detects Next.js App Router routes and methods', () => {
  withTempProject((root) => {
    mkdirSync(join(root, 'app/api/users'), { recursive: true });
    writeFileSync(join(root, 'app/api/users/route.ts'), `
import { NextResponse } from 'next/server';

export async function GET(request: Request) {
  const data = await fetch('https://internal.service/users');
  return NextResponse.json(await data.json());
}

export const POST = async (request: Request) => {
  const body = await request.json();
  eval(body.snippet); // airtight-disable-line js/eval-dynamic
  return NextResponse.json({ status: 'ok' });
};
    `);

    const result = generateAttackSurfaceMap(['app'], { root });
    assert.equal(result.summary.totalRoutes, 2);
    assert.deepEqual(result.summary.frameworks, ['nextjs']);
    assert.equal(result.summary.totalSinksNearRoutes, 2);

    const [getRoute, postRoute] = result.routes;
    assert.equal(getRoute.method, 'GET');
    assert.equal(getRoute.path, '/api/users');
    assert.equal(getRoute.sinks.length, 1);
    assert.equal(getRoute.sinks[0].type, 'ssrf');

    assert.equal(postRoute.method, 'POST');
    assert.equal(postRoute.path, '/api/users');
    assert.equal(postRoute.sinks.length, 1);
    assert.equal(postRoute.sinks[0].type, 'eval');
  });
});

test('generateAttackSurfaceMap detects Flask endpoints and methods', () => {
  withTempProject((root) => {
    mkdirSync(join(root, 'api'), { recursive: true });
    writeFileSync(join(root, 'api/routes.py'), `
from flask import Flask, Blueprint, request
app = Flask(__name__)
bp = Blueprint('api', __name__)

@app.route('/status')
def get_status():
    return {'status': 'ok'}

@bp.route('/execute', methods=['POST', 'PUT'])
def run_command():
    cmd = request.json['cmd']
    os.system(cmd)
    return 'done'
    `);

    const result = generateAttackSurfaceMap(['api'], { root });
    assert.equal(result.summary.totalRoutes, 3); // GET /status, POST /execute, PUT /execute
    assert.deepEqual(result.summary.frameworks, ['flask']);
    assert.equal(result.summary.totalSinksNearRoutes, 1);

    const execRoute = result.routes.find((r) => r.path === '/execute');
    assert.ok(execRoute);
    assert.equal(execRoute.handlerName, 'run_command');
    assert.equal(execRoute.sinks.length, 1);
    assert.equal(execRoute.sinks[0].type, 'exec');
  });
});

test('generateAttackSurfaceMap detects FastAPI endpoints', () => {
  withTempProject((root) => {
    mkdirSync(join(root, 'app'), { recursive: true });
    writeFileSync(join(root, 'app/main.py'), `
from fastapi import FastAPI, APIRouter
app = FastAPI()
router = APIRouter()

@app.get('/items/{item_id}')
async def read_item(item_id: int):
    with open('/tmp/cache.json', 'r') as f:
        return f.read()

@router.delete('/items/{item_id}')
def delete_item(item_id: int):
    return {'deleted': item_id}
    `);

    const result = generateAttackSurfaceMap(['app'], { root });
    assert.equal(result.summary.totalRoutes, 2);
    assert.deepEqual(result.summary.frameworks, ['fastapi']);

    const [r1, r2] = result.routes;
    assert.equal(r1.method, 'GET');
    assert.equal(r1.path, '/items/{item_id}');
    assert.equal(r1.handlerName, 'read_item');
    assert.equal(r1.sinks.length, 1);
    assert.equal(r1.sinks[0].type, 'file');

    assert.equal(r2.method, 'DELETE');
    assert.equal(r2.path, '/items/{item_id}');
    assert.equal(r2.handlerName, 'delete_item');
  });
});

test('generateAttackSurfaceMap detects Django urls.py patterns', () => {
  withTempProject((root) => {
    mkdirSync(join(root, 'myproject'), { recursive: true });
    writeFileSync(join(root, 'myproject/urls.py'), `
from django.urls import path, re_path
from . import views

urlpatterns = [
    path('users/', views.list_users, name='user-list'),
    re_path(r'^items/(?P<id>[0-9]+)/$', views.ItemDetailView.as_view()),
]
    `);

    const result = generateAttackSurfaceMap(['myproject'], { root });
    assert.equal(result.summary.totalRoutes, 2);
    assert.deepEqual(result.summary.frameworks, ['django']);

    const [r1, r2] = result.routes;
    assert.equal(r1.method, 'ALL');
    assert.equal(r1.path, 'users/');
    assert.equal(r1.handlerName, 'views.list_users');

    assert.equal(r2.method, 'ALL');
    assert.equal(r2.path, '^items/(?P<id>[0-9]+)/$');
  });
});

test('generateAttackSurfaceMap detects Gin routes in Go', () => {
  withTempProject((root) => {
    mkdirSync(join(root, 'server'), { recursive: true });
    writeFileSync(join(root, 'server/main.go'), `
package main

import (
	"net/http"
	"os/exec"
	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()
	r.GET("/health", healthCheck)
	v1 := r.Group("/v1")
	v1.POST("/run", func(c *gin.Context) {
		cmd := exec.Command("sh", "-c", "echo hi")
		cmd.Run()
	})
}
    `);

    const result = generateAttackSurfaceMap(['server'], { root });
    assert.equal(result.summary.totalRoutes, 3);
    assert.deepEqual(result.summary.frameworks, ['gin']);

    const runRoute = result.routes.find((r) => r.path === '/run');
    assert.ok(runRoute);
    assert.equal(runRoute.method, 'POST');
    assert.equal(runRoute.sinks.length, 1);
    assert.equal(runRoute.sinks[0].type, 'exec');
  });
});

test('generateAttackSurfaceMap detects Spring mappings in Java', () => {
  withTempProject((root) => {
    mkdirSync(join(root, 'src/main/java/com/example'), { recursive: true });
    writeFileSync(join(root, 'src/main/java/com/example/UserController.java'), `
package com.example;

import org.springframework.web.bind.annotation.*;
import java.util.List;

@RestController
@RequestMapping("/api/v1")
public class UserController {

    @GetMapping("/users")
    public List<String> listUsers() {
        return jdbcTemplate.query("SELECT name FROM users", mapper);
    }

    @PostMapping("/users")
    public void createUser(@RequestBody User user) {
    }
}
    `);

    const result = generateAttackSurfaceMap(['src'], { root });
    assert.equal(result.summary.totalRoutes, 2);
    assert.deepEqual(result.summary.frameworks, ['spring']);

    const [r1, r2] = result.routes;
    assert.equal(r1.method, 'GET');
    assert.equal(r1.path, '/api/v1/users');
    assert.equal(r1.handlerName, 'listUsers');
    assert.equal(r1.sinks.length, 1);
    assert.equal(r1.sinks[0].type, 'sql');

    assert.equal(r2.method, 'POST');
    assert.equal(r2.path, '/api/v1/users');
    assert.equal(r2.handlerName, 'createUser');
  });
});

test('generateAttackSurfaceMap handles multi-framework project and summary statistics', () => {
  withTempProject((root) => {
    mkdirSync(join(root, 'express'), { recursive: true });
    mkdirSync(join(root, 'django'), { recursive: true });

    writeFileSync(join(root, 'express/index.js'), `
app.get('/api', handler);
    `);
    writeFileSync(join(root, 'django/urls.py'), `
path('admin/', admin.site.urls)
    `);

    const result = generateAttackSurfaceMap(['.'], { root });
    assert.equal(result.summary.totalRoutes, 2);
    assert.deepEqual(result.summary.frameworks, ['django', 'express']);
    assert.equal(result.summary.totalSinksNearRoutes, 0);
  });
});

test('generateAttackSurfaceMap handles empty projects and non-route files', () => {
  withTempProject((root) => {
    mkdirSync(join(root, 'util'), { recursive: true });
    // File with a sink but no routes
    writeFileSync(join(root, 'util/db.js'), `
const { exec } = require('child_process');
exec('ls');
    `);

    // Empty dir
    const result1 = generateAttackSurfaceMap([], { root });
    assert.equal(result1.summary.totalRoutes, 0);
    assert.deepEqual(result1.summary.frameworks, []);
    assert.equal(result1.summary.totalSinksNearRoutes, 0);

    // Path as single string
    const result2 = generateAttackSurfaceMap('util', { root });
    assert.equal(result2.summary.totalRoutes, 0);
    assert.equal(result2.summary.totalSinksNearRoutes, 0);
  });
});

test('generateAttackSurfaceMap detects NestJS controllers, routes, and parameter annotations', () => {
  withTempProject((root) => {
    mkdirSync(join(root, 'src'), { recursive: true });
    writeFileSync(join(root, 'src/users.controller.ts'), `
import { Controller, Get, Post, Put, Delete, Patch, All, Body, Param, Query } from '@nestjs/common';

@Controller('api/v1/users')
export class UsersController {
  @Get(':id')
  async findOne(@Param('id') id: string, @Query('include') include: string) {
    return this.dataSource.query('SELECT * FROM users WHERE id = $1', [id]);
  }

  @Post()
  async create(@Body() createUserDto: any) {
    return { status: 'created' };
  }

  @Put(':id')
  async update(@Param('id') id: string, @Body() updateDto: any) {
    return { status: 'updated' };
  }

  @Delete(':id')
  async remove(@Param('id') id: string) {
    return { status: 'deleted' };
  }

  @Patch(':id')
  async patch(@Param('id') id: string, @Body() patchDto: any) {
    return { status: 'patched' };
  }

  @All('proxy')
  async proxyAll() {
    return { status: 'proxied' };
  }
}
    `);

    writeFileSync(join(root, 'src/health.controller.ts'), `
import { Controller, Get } from '@nestjs/common';

@Controller()
export class HealthController {
  @Get('health')
  check() {
    return { status: 'ok' };
  }
}
    `);

    const result = generateAttackSurfaceMap(['src'], { root });
    assert.equal(result.summary.totalRoutes, 7);
    assert.deepEqual(result.summary.frameworks, ['nestjs']);
    assert.equal(result.summary.totalSinksNearRoutes, 1);

    const routes = result.routes;
    const findOneRoute = routes.find((r) => r.method === 'GET' && r.path === '/api/v1/users/:id');
    assert.ok(findOneRoute);
    assert.equal(findOneRoute.handlerName, 'findOne');
    assert.ok(findOneRoute.params.includes('@Param()'));
    assert.ok(findOneRoute.params.includes('@Query()'));
    assert.equal(findOneRoute.sinks.length, 1);
    assert.equal(findOneRoute.sinks[0].type, 'sql');

    const createRoute = routes.find((r) => r.method === 'POST' && r.path === '/api/v1/users');
    assert.ok(createRoute);
    assert.equal(createRoute.handlerName, 'create');
    assert.ok(createRoute.params.includes('@Body()'));

    const putRoute = routes.find((r) => r.method === 'PUT' && r.path === '/api/v1/users/:id');
    assert.ok(putRoute);
    assert.equal(putRoute.handlerName, 'update');
    assert.ok(putRoute.params.includes('@Param()'));
    assert.ok(putRoute.params.includes('@Body()'));

    const deleteRoute = routes.find((r) => r.method === 'DELETE' && r.path === '/api/v1/users/:id');
    assert.ok(deleteRoute);
    assert.equal(deleteRoute.handlerName, 'remove');
    assert.ok(deleteRoute.params.includes('@Param()'));

    const patchRoute = routes.find((r) => r.method === 'PATCH' && r.path === '/api/v1/users/:id');
    assert.ok(patchRoute);
    assert.equal(patchRoute.handlerName, 'patch');
    assert.ok(patchRoute.params.includes('@Param()'));
    assert.ok(patchRoute.params.includes('@Body()'));

    const proxyRoute = routes.find((r) => r.method === 'ALL' && r.path === '/api/v1/users/proxy');
    assert.ok(proxyRoute);
    assert.equal(proxyRoute.handlerName, 'proxyAll');

    const healthRoute = routes.find((r) => r.path === '/health');
    assert.ok(healthRoute);
    assert.equal(healthRoute.method, 'GET');
    assert.equal(healthRoute.handlerName, 'check');
  });
});

test('generateAttackSurfaceMap detects Next.js Pages Router and Server Actions', () => {
  withTempProject((root) => {
    // 1. Pages Router
    mkdirSync(join(root, 'pages/api/users'), { recursive: true });
    writeFileSync(join(root, 'pages/api/users/[id].ts'), `
export default async function handler(req, res) {
  const { id } = req.query;
  res.status(200).json({ id });
}
    `);

    // 2. Server Action (file-level 'use server')
    mkdirSync(join(root, 'app/actions'), { recursive: true });
    writeFileSync(join(root, 'app/actions/projects.ts'), `
'use server';

export async function deleteProject(projectId: string) {
  return { success: true };
}

export const createProject = async (name: string) => {
  return { id: 123, name };
};
    `);

    // 3. Inline Server Action in component
    mkdirSync(join(root, 'app/dashboard'), { recursive: true });
    writeFileSync(join(root, 'app/dashboard/page.tsx'), `
export default function Dashboard() {
  async function submitForm(formData: FormData) {
    'use server';
    // perform mutation
  }
  return <form action={submitForm}><button type="submit">Go</button></form>;
}
    `);

    const result = generateAttackSurfaceMap(['pages', 'app'], { root });
    assert.equal(result.summary.totalRoutes, 4);
    assert.deepEqual(result.summary.frameworks, ['nextjs']);

    const pagesRoute = result.routes.find((r) => r.path === '/api/users/:id');
    assert.ok(pagesRoute);
    assert.equal(pagesRoute.method, 'ALL');
    assert.equal(pagesRoute.handlerName, 'handler');

    const delAction = result.routes.find((r) => r.handlerName === 'deleteProject');
    assert.ok(delAction);
    assert.equal(delAction.method, 'POST');
    assert.equal(delAction.path, '/deleteProject');

    const createAction = result.routes.find((r) => r.handlerName === 'createProject');
    assert.ok(createAction);
    assert.equal(createAction.method, 'POST');
    assert.equal(createAction.path, '/createProject');

    const submitAction = result.routes.find((r) => r.handlerName === 'submitForm');
    assert.ok(submitAction);
    assert.equal(submitAction.method, 'POST');
    assert.equal(submitAction.path, '/submitForm');
  });
});

test('generateAttackSurfaceMap detects Cloudflare Pages Functions routes', () => {
  withTempProject((root) => {
    mkdirSync(join(root, 'functions/api/users'), { recursive: true });
    writeFileSync(join(root, 'functions/api/submit.ts'), `
export async function onRequestPost(context) {
  const data = await context.request.json();
  return new Response('ok');
}

export async function onRequestGet(context) {
  return new Response('submit form');
}
    `);

    writeFileSync(join(root, 'functions/api/users/[id].ts'), `
export const onRequestDelete = async (context) => {
  return new Response('deleted');
};

export async function onRequestPut(context) {
  return new Response('updated');
}
    `);

    writeFileSync(join(root, 'functions/api/fallback.js'), `
export async function onRequest(context) {
  return new Response('fallback');
}
    `);

    const result = generateAttackSurfaceMap(['functions'], { root });
    assert.equal(result.summary.totalRoutes, 5);
    assert.deepEqual(result.summary.frameworks, ['cloudflare']);

    const postRoute = result.routes.find((r) => r.path === '/api/submit' && r.method === 'POST');
    assert.ok(postRoute);
    assert.equal(postRoute.handlerName, 'onRequestPost');

    const getRoute = result.routes.find((r) => r.path === '/api/submit' && r.method === 'GET');
    assert.ok(getRoute);
    assert.equal(getRoute.handlerName, 'onRequestGet');

    const deleteRoute = result.routes.find((r) => r.path === '/api/users/:id' && r.method === 'DELETE');
    assert.ok(deleteRoute);
    assert.equal(deleteRoute.handlerName, 'onRequestDelete');

    const putRoute = result.routes.find((r) => r.path === '/api/users/:id' && r.method === 'PUT');
    assert.ok(putRoute);
    assert.equal(putRoute.handlerName, 'onRequestPut');

    const fallbackRoute = result.routes.find((r) => r.path === '/api/fallback');
    assert.ok(fallbackRoute);
    assert.equal(fallbackRoute.method, 'ALL');
    assert.equal(fallbackRoute.handlerName, 'onRequest');
  });
});

