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

