import { PoolTimeoutError } from "../errors";
import { addBreadcrumb } from "../sentry";

class BoundedConnectionPool {
  private leased = 0;

  constructor(private readonly capacity: number) {}

  acquire(label: string): string {
    addBreadcrumb("connection acquire requested", {
      label,
      leased: this.leased,
      capacity: this.capacity
    });

    if (this.leased >= this.capacity) {
      throw new PoolTimeoutError(
        `pool exhausted after ${this.capacity} active message connections; timed out acquiring ${label}`
      );
    }

    this.leased += 1;
    return `conn_${label}_${this.leased}`;
  }

  release(): void {
    this.leased = Math.max(0, this.leased - 1);
  }
}

export async function sendBurstThroughPool(): Promise<void> {
  const pool = new BoundedConnectionPool(5);
  const leased: string[] = [];

  for (let index = 0; index < 7; index += 1) {
    await new Promise((resolve) => setTimeout(resolve, 2));
    leased.push(pool.acquire(`burst_${index + 1}`));
  }

  for (const _connection of leased) {
    pool.release();
  }
}
