import { DataSource, EntityManager } from 'typeorm';

export class SafeUserService {
  constructor(private dataSource: DataSource, private entityManager: EntityManager) {}

  async findUsers(userId: string, token: string, id: string) {
    const users = await this.dataSource.query("SELECT * FROM users WHERE id = $1", [userId]);
    await this.dataSource.query('DELETE FROM sessions WHERE token = ?', [token]);
    const res = await this.entityManager.query("SELECT * FROM items WHERE status = $1", ['active']);
    await this.entityManager.query('SELECT * FROM accounts');
    const logs = await customService.query(`SELECT * FROM logs WHERE id = ${id}`);
    // await this.dataSource.query(`SELECT * FROM users WHERE id = ${id}`);
  }
}
