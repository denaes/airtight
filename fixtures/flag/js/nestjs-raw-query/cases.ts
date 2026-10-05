import { DataSource, EntityManager } from 'typeorm';

export class UserService {
  constructor(private dataSource: DataSource, private entityManager: EntityManager) {}

  async findUsers(userId: string, token: string, name: string, amt: number) {
    const users = await this.dataSource.query(`SELECT * FROM users WHERE id = ${userId}`);
    await this.dataSource.query(`DELETE FROM sessions WHERE token = '${token}'`);
    const res = await this.entityManager.query("SELECT * FROM items WHERE name = " + name);
    await this.entityManager.query('UPDATE accounts SET balance = ' + amt);
  }
}
