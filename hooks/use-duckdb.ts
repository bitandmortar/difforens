import * as duckdb from '@duckdb/duckdb-wasm';
import { useState, useEffect } from 'react';

export function useDuckDB() {
  const [db, setDb] = useState<duckdb.AsyncDuckDB | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);

  useEffect(() => {
    async function initDb() {
      try {
        const JSDELIVR_BUNDLES = duckdb.getJsDelivrBundles();
        const bundle = await duckdb.selectBundle(JSDELIVR_BUNDLES);
        
        const worker_url = URL.createObjectURL(
          new Blob([`importScripts("${bundle.mainWorker!}");`], {
            type: 'text/javascript',
          })
        );

        const worker = new Worker(worker_url);
        const logger = new duckdb.ConsoleLogger();
        const database = new duckdb.AsyncDuckDB(logger, worker);
        await database.instantiate(bundle.mainModule, bundle.pthreadWorker);
        URL.revokeObjectURL(worker_url);
        
        setDb(database);
        setIsLoading(false);
      } catch (err) {
        console.error("DuckDB Init Error", err);
        setError(err instanceof Error ? err : new Error(String(err)));
        setIsLoading(false);
      }
    }

    initDb();
  }, []);

  return { db, isLoading, error };
}
