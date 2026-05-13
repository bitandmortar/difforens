self.onmessage = async (e) => {
  const { type, payload } = e.data;
  
  if (type === 'PROCESS_REPORT') {
    try {
      const { text } = payload;
      const json = JSON.parse(text);
      if (!json.metadata || (!json.files && !json.data)) {
        throw new Error("Invalid structure");
      }
      self.postMessage({ type: 'PROCESS_REPORT_SUCCESS', payload: json });
    } catch (err) {
      self.postMessage({ type: 'PROCESS_REPORT_ERROR', error: err.message });
    }
  } else if (type === 'COMPUTE_DIFF') {
    try {
      const { filesA, filesB } = payload;
      
      const mapA = new Map();
      const mapB = new Map();
      
      // We will perform mapping asynchronously in chunks to prevent freezing the worker
      // and allow progress reporting.
      
      const CHUNK_SIZE = 10000;
      
      const processMap = async (files, targetMap, stepName) => {
        for (let i = 0; i < files.length; i += CHUNK_SIZE) {
          const chunk = files.slice(i, i + CHUNK_SIZE);
          for (const f of chunk) {
            targetMap.set(f.path, f);
          }
          self.postMessage({ type: 'COMPUTE_DIFF_PROGRESS', payload: { step: stepName, processed: i + chunk.length, total: files.length } });
          await new Promise(resolve => setTimeout(resolve, 0)); // yield
        }
      };

      await processMap(filesA, mapA, 'Mapping Report A');
      await processMap(filesB, mapB, 'Mapping Report B');
      
      const added = [];
      const removed = [];
      const modified = [];
      const identical = [];
      
      const bEntries = Array.from(mapB.entries());
      for (let i = 0; i < bEntries.length; i += CHUNK_SIZE) {
        const chunk = bEntries.slice(i, i + CHUNK_SIZE);
        for (const [path, fileB] of chunk) {
          const fileA = mapA.get(path);
          if (!fileA) {
            added.push(fileB);
          } else {
            if (fileB.sha256 && fileA.sha256 && fileB.sha256 === fileA.sha256) {
              identical.push(fileB);
            } else if (fileB.size === fileA.size && fileB.modified === fileA.modified && !fileB.sha256) {
               identical.push(fileB);
            } else {
              modified.push({ a: fileA, b: fileB, path });
            }
          }
        }
        self.postMessage({ type: 'COMPUTE_DIFF_PROGRESS', payload: { step: 'Comparing B against A', processed: Math.min(i + CHUNK_SIZE, bEntries.length), total: bEntries.length } });
        await new Promise(resolve => setTimeout(resolve, 0)); // yield
      }
      
      const aEntries = Array.from(mapA.entries());
      for (let i = 0; i < aEntries.length; i += CHUNK_SIZE) {
        const chunk = aEntries.slice(i, i + CHUNK_SIZE);
        for (const [path, fileA] of chunk) {
          if (!mapB.has(path)) {
            removed.push(fileA);
          }
        }
        self.postMessage({ type: 'COMPUTE_DIFF_PROGRESS', payload: { step: 'Checking removed files', processed: Math.min(i + CHUNK_SIZE, aEntries.length), total: aEntries.length } });
        await new Promise(resolve => setTimeout(resolve, 0)); // yield
      }
      
      self.postMessage({ 
        type: 'COMPUTE_DIFF_SUCCESS', 
        payload: { added, removed, modified, identical } 
      });
      
    } catch (err) {
      self.postMessage({ type: 'COMPUTE_DIFF_ERROR', error: err.message });
    }
  }
};
