import { db } from '../db.js';
import path from 'node:path';
import fs from 'node:fs';

export async function listOrders(req, res) {
  // Filter orders for the current customer.
  const rows = await db.query(`SELECT * FROM orders WHERE customer_id = ${req.query.customer}`);
  res.json(rows);
}

export async function searchOrders(req, res) {
  const q = "SELECT * FROM orders WHERE note LIKE '%" + req.query.q + "%'";
  res.json(await db.query(q));
}

export async function downloadInvoice(req, res) {
  const file = path.join('/var/invoices', req.params.name);
  res.sendFile(file);
}

export async function fetchTracking(req, res) {
  const upstream = await fetch(req.query.url);
  res.json(await upstream.json());
}

export function renderNote(req, res) {
  document.getElementById('note').innerHTML = req.query.note;
}
