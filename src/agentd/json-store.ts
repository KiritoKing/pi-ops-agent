import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

export class JsonFileStore<Value> {
  readonly #path: string;
  readonly #parse: (value: unknown) => Value;
  readonly #empty: () => Value;
  #queue: Promise<void> = Promise.resolve();

  constructor(path: string, parse: (value: unknown) => Value, empty: () => Value) {
    this.#path = path;
    this.#parse = parse;
    this.#empty = empty;
  }

  async initialize(): Promise<void> {
    await mkdir(dirname(this.#path), { recursive: true, mode: 0o750 });
    try {
      await this.read();
    } catch (error) {
      if (!(error instanceof Error && "code" in error && error.code === "ENOENT")) throw error;
      await this.write(this.#empty());
    }
  }

  async read(): Promise<Value> {
    const parsed = JSON.parse(await readFile(this.#path, "utf8")) as unknown;
    return this.#parse(parsed);
  }

  async update(mutator: (current: Value) => Value): Promise<Value> {
    const result = Promise.withResolvers<Value>();
    this.#queue = this.#queue.then(async () => {
      const next = mutator(await this.read());
      await this.#writeImmediately(next);
      result.resolve(next);
    }).catch((error: unknown) => result.reject(error));
    return await result.promise;
  }

  async write(value: Value): Promise<void> {
    const result = Promise.withResolvers<undefined>();
    this.#queue = this.#queue.then(async () => {
      await this.#writeImmediately(value);
      result.resolve(undefined);
    }).catch((error: unknown) => result.reject(error));
    await result.promise;
  }

  async #writeImmediately(value: Value): Promise<void> {
    const temporary = `${this.#path}.tmp-${process.pid}`;
    await writeFile(temporary, `${JSON.stringify(value, undefined, 2)}\n`, {
      encoding: "utf8",
      mode: 0o600,
    });
    await rename(temporary, this.#path);
  }
}
