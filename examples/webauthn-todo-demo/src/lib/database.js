import { IPFSAccessController } from '@orbitdb/core';
import { logger } from '@libp2p/logger';

// Create database logger
const dbLog = logger('orbitdb-identity-provider-webauthn-did:database');

// Global store for identity verification results (not persisted)
const identityVerifications = new Map(); // Map<todoId, {verified: boolean, timestamp: number, identityHash: string}>

// Export function to access verification store from UI
export function getIdentityVerifications() {
  return identityVerifications;
}

export function getVerificationForTodo(todoId) {
  return identityVerifications.get(todoId) || null;
}

/**
 * Opens a TODO database with the given OrbitDB instance and identity
 * @param {Object} orbitdb - The OrbitDB instance
 * @param {Object} identity - The WebAuthn identity
 * @param {Object} identities - The OrbitDB identities instance
 * @returns {Object} The opened database instance
 */
export async function openTodoDatabase(orbitdb, identity, identities) {
  // Store references for later use in event handlers
  const ipfsInstance = orbitdb.ipfs;
  const writePermissions = [identity.id];

  console.log('🔓 Database access configuration:', {
    writePermissions,
    identityId: identity.id,
    identityType: identity.type,
  });

  console.log('📝 Opening database "webauthn-todos"...');

  const database = await Promise.race([
    orbitdb.open('webauthn-todos', {
      type: 'keyvalue',
      create: true,
      sync: true,
      accessController: IPFSAccessController({
        write: writePermissions,
      }),
    }),
    new Promise((_, reject) =>
      setTimeout(
        () => reject(new Error('Database open timeout after 15 seconds')),
        15000
      )
    ),
  ]);

  console.log('✅ Database opened successfully:', {
    name: database.name,
    address: database.address,
    type: database.type,
    identityId: database.identity?.id,
    accessControllerType: database.access?.type,
  });

  // Set up database event listeners for debugging
  setupDatabaseEventListeners(database, ipfsInstance, identities);

  return database;
}

/**
 * Sets up event listeners for database debugging
 * @param {Object} database - The database instance
 * @param {Object} ipfs - The IPFS/Helia instance
 * @param {Object} identities - The OrbitDB identities instance
 */
function setupDatabaseEventListeners(database, ipfs, identities) {
  database.events.on('join', (address, entry) => {
    console.log('🔗 Database JOIN event:', { address, entry: entry?.key });
  });

  database.events.on('update', async (address) => {
    console.log('🔄 Database UPDATE event:', { address });

    // Get the identity hash from the update event
    const updateIdentityHash = address?.identity;
    if (!updateIdentityHash) {
      console.warn('⚠️ Update event missing identity information');
      return;
    }

    // Get our WebAuthn DID from the database's identity
    const webAuthnDID = database.identity.id;
    if (!webAuthnDID) {
      console.warn('⚠️ Database missing identity information');
      return;
    }

    // Import verification utilities and verify the identity
    try {
      // Use pragmatic verification to avoid network timeouts
      const { verifyDatabaseUpdate } = await import('./verification.js');
      const verification = await verifyDatabaseUpdate(database, updateIdentityHash, webAuthnDID);
      
      // Find which todo was just updated by checking the latest entries
      let updatedTodoId = null;
      try {
        const allEntries = await database.all();
        // Find the most recent entry - this should be the one that triggered the update
        const latestEntry = allEntries
          .sort((a, b) => new Date(b.value.createdAt) - new Date(a.value.createdAt))[0];
        updatedTodoId = latestEntry?.key;
      } catch (error) {
        console.warn('Could not determine which todo was updated:', error);
      }
      
      // Persist verification outcome in ephemeral map for UI
      if (updatedTodoId) {
        identityVerifications.set(updatedTodoId, {
          success: verification.success,
          timestamp: Date.now(),
          identityHash: updateIdentityHash,
          error: verification.error || null,
          method: verification.method
        });
        console.log(`💾 Stored verification for todo ${updatedTodoId}: ${verification.success ? 'PASSED' : 'FAILED'}`);
      }
      
    } catch (identityError) {
      console.error('❌ Error retrieving identity from OrbitDB:', identityError);
      // Store error result for failed verification
      const updatedTodoId = 'unknown';
      identityVerifications.set(updatedTodoId, {
        success: false,
        identityHash: updateIdentityHash,
        timestamp: Date.now(),
        error: `Identity verification failed: ${identityError.message}`,
        method: 'error-fallback'
      });
    }
  });

  database.events.on('error', (error) => {
    console.error('❌ Database ERROR event:', error);
  });
}

/**
 * Loads all todos from the database
 * @param {Object} database - The database instance
 * @returns {Array} Array of todo objects
 */
export async function loadTodos(database) {
  if (!database) return [];

  try {
    console.log('📊 Loading todos from database:', {
      databaseName: database.name,
      databaseAddress: database.address,
      databaseType: database.type,
      identityId: database.identity?.id,
      accessController: database.access?.type,
    });

    console.log('⏳ Calling database.all()...');
    const allTodos = await Promise.race([
      database.all(),
      new Promise((_, reject) =>
        setTimeout(
          () => reject(new Error('Database.all() timeout after 10 seconds')),
          10000
        )
      ),
    ]);

    console.log('✅ Database.all() completed, entries found:', allTodos.length);

    const todos = allTodos
      .map((entry) => {
        console.log('📝 Todo entry:', { key: entry.key, value: entry.value });
        return entry.value;
      })
      .sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt));

    console.log('📋 Todos loaded successfully:', todos.length);
    return todos;
  } catch (error) {
    console.error('❌ Failed to load todos:', error);
    console.error('Error details:', {
      message: error.message,
      name: error.name,
      stack: error.stack?.slice(0, 500),
    });

    // Re-throw the error so the caller can handle it
    throw error;
  }
}

/**
 * Adds a new todo to the database
 * @param {Object} database - The database instance
 * @param {string} text - The todo text
 * @param {Object} credential - The WebAuthn credential (for debugging)
 * @returns {Object} The created todo object
 */
export async function addTodo(database, text, credential = null) {
  if (!database || !text.trim()) {
    throw new Error('Database and todo text are required');
  }

  try {
    const startTime = Date.now();

    const todoId = `todo-${Date.now()}`;
    const todo = {
      id: todoId,
      text: text.trim(),
      completed: false,
      createdAt: new Date().toISOString(),
    };

    dbLog('addTodo() called: %o', { todoId, textLength: text.trim().length });
    dbLog('Identity context: %o', {
      providerType: database.identity?.type,
      providerIdPrefix: database.identity?.id?.slice?.(0, 16),
      hasKeystore: Boolean(database.identities?.keystore),
      keystoreType: database.identities?.keystore?.type || null
    });
    dbLog('Calling database.put() - this will trigger: db.put() → identity.sign() → signIdentity() → webauthnProvider.sign()');

    await database.put(todoId, todo);

    const endTime = Date.now();
    dbLog('database.put() completed in %d ms', endTime - startTime);

    return todo;
  } catch (error) {
    console.error('Failed to add todo:', error);
    throw error;
  }
}

/**
 * Toggles the completed status of a todo
 * @param {Object} database - The database instance
 * @param {Object} todo - The todo object to toggle
 * @returns {Object} The updated todo object
 */
export async function toggleTodo(database, todo) {
  if (!database || !todo) {
    throw new Error('Database and todo are required');
  }

  try {
    const startTime = Date.now();

    const updatedTodo = {
      ...todo,
      completed: !todo.completed,
    };

    dbLog('toggleTodo() called for todo: %s', todo.id);
    dbLog('Identity context: %o', {
      providerType: database.identity?.type,
      providerIdPrefix: database.identity?.id?.slice?.(0, 16),
      hasKeystore: Boolean(database.identities?.keystore),
      keystoreType: database.identities?.keystore?.type || null
    });
    dbLog('Calling database.put() - this will trigger: db.put() → identity.sign() → signIdentity() → webauthnProvider.sign()');

    await database.put(todo.id, updatedTodo);

    const endTime = Date.now();
    dbLog('database.put() completed in %d ms', endTime - startTime);

    return updatedTodo;
  } catch (error) {
    console.error('Failed to toggle todo:', error);
    throw error;
  }
}

/**
 * Deletes a todo from the database
 * @param {Object} database - The database instance
 * @param {Object} todo - The todo object to delete
 */
export async function deleteTodo(database, todo) {
  if (!database || !todo) {
    throw new Error('Database and todo are required');
  }

  try {
    const startTime = Date.now();

    dbLog('deleteTodo() called for todo: %s', todo.id);
    dbLog('Identity context: %o', {
      providerType: database.identity?.type,
      providerIdPrefix: database.identity?.id?.slice?.(0, 16),
      hasKeystore: Boolean(database.identities?.keystore),
      keystoreType: database.identities?.keystore?.type || null
    });
    dbLog('Calling database.del() - this will trigger: db.del() → identity.sign() → signIdentity() → webauthnProvider.sign()');

    await database.del(todo.id);

    const endTime = Date.now();
    dbLog('database.del() completed in %d ms', endTime - startTime);
  } catch (error) {
    dbLog.error('Failed to delete todo: %s', error.message);
    throw error;
  }
}

/**
 * Gets statistics about the todos
 * @param {Array} todos - Array of todo objects
 * @returns {Object} Statistics object
 */
export function getTodoStats(todos) {
  return {
    total: todos.length,
    completed: todos.filter((t) => t.completed).length,
    remaining: todos.filter((t) => !t.completed).length,
  };
}
